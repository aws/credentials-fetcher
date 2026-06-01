package kerberos

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/constants"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/config_utils"

	"golang.a2z.com/CredentialsFetcherV2/internal/auth/ldap"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/aws_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/krb_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/metadata_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

var (
	log = logger.GetInstance()
)

// Define an interface that matches the methods we need to mock
type LdapClientInterface interface {
	FindDN(ctx context.Context, serviceAccount, baseDN, fqdn string) (string, error)
	SearchGMSAPassword(ctx context.Context, dn, fqdn string, executor interface{}) ([]byte, error)
}

var (
	readMetadataJSONFunc     = metadata_utils.ReadMetadataJSON
	getMetadataFilePathsFunc = metadata_utils.GetMetadataFilePaths
	getFQDNListFunc          = grpc_utils.GetFQDNList
	newLdapClientFunc        = ldap.NewClient
	// getTicketsFromMetadataFunc is mockable for testing CleanupOrphanedTickets
	getTicketsFromMetadataFunc func(c *Client, metadataPath string) ([]*types.Ticket, []*types.TicketInfo, error) = (*Client).GetTicketsFromMetadata
)

// Client provides Kerberos authentication operations using CGO-based krb_utils package
// for ticket creation and renewal, while maintaining shell-based operations for
// ticket deletion to preserve existing functionality.
type Client struct {
	// shellExecutor is retained only for DeleteKerberosLease functionality
	// All other Kerberos operations use the CGO-based krb_utils package
	shellExecutor cmdexec.Executor
	// krb5Client allows dependency injection for testing
	krb5Client krb_utils.Krb5Client
}

// NewClient creates a new Kerberos client that uses CGO-based krb_utils package
func NewClient() *Client {
	return &Client{
		shellExecutor: cmdexec.NewExecutor(),
		krb5Client:    krb_utils.DefaultKrb5Client,
	}
}

// NewClientWithKrb5Client creates a new client with a custom Krb5Client for testing
func NewClientWithKrb5Client(krb5Client krb_utils.Krb5Client) *Client {
	return &Client{
		shellExecutor: cmdexec.NewExecutor(),
		krb5Client:    krb5Client,
	}
}

// translateKrbUtilsError wraps krb_utils package errors with additional context
func (c *Client) translateKrbUtilsError(err error, operation string) error {
	if err == nil {
		return nil
	}

	// Wrap krb_utils errors with context
	return fmt.Errorf("failed to %s: %w", operation, err)
}

// ensureUserCacheDirectory creates the user cache directory if it doesn't exist
// and sets appropriate permissions for security
func (c *Client) ensureUserCacheDirectory(cacheDir string) error {
	// Check if directory exists
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		// Create directory with restrictive permissions (only owner can access)
		if err := os.MkdirAll(cacheDir, 0700); err != nil {
			log.Error("Failed to create user cache directory",
				"directory", cacheDir,
				"error", err)
			return fmt.Errorf("failed to create user cache directory %s: %w", cacheDir, err)
		}
		log.Info("Created user cache directory", "directory", cacheDir)
	} else if err != nil {
		log.Error("Failed to check user cache directory",
			"directory", cacheDir,
			"error", err)
		return fmt.Errorf("failed to check user cache directory %s: %w", cacheDir, err)
	}

	// Ensure directory has correct permissions (owner read/write/execute only)
	// #nosec G302 - 0700 is appropriate for directories (owner read/write/execute only)
	if err := os.Chmod(cacheDir, 0700); err != nil {
		log.Warn("Failed to set permissions on user cache directory",
			"directory", cacheDir,
			"error", err)
		// Don't fail here, just warn - the directory might still be usable
	}

	return nil
}

// setKrb5CCNameForUserCache sets the KRB5CCNAME environment variable to point to the user cache
// Returns the original value so it can be restored later
func (c *Client) setKrb5CCNameForUserCache(cachePath string) string {
	originalValue := os.Getenv("KRB5CCNAME")
	newValue := "FILE:" + cachePath

	if err := os.Setenv("KRB5CCNAME", newValue); err != nil {
		log.Warn("Failed to set KRB5CCNAME environment variable",
			"error", err,
			"cache_path", cachePath)
		return originalValue
	}

	log.Info("Set KRB5CCNAME environment variable for LDAP operations",
		"cache_path", cachePath,
		"original_value", originalValue,
		"new_value", newValue)

	return originalValue
}

// GetTicket retrieves comprehensive information about a Kerberos ticket from a file
func (c *Client) GetTicket(path string) (*types.Ticket, *types.TicketInfo, error) {
	log.Debug("Reading ticket info using klist", "path", path)

	ctx := context.Background()

	// Use the cmdexec package to execute the klist command
	output, err := c.shellExecutor.Execute(ctx, "klist", "-c", path)
	if err != nil {
		log.Error("Klist command failed",
			"error", err,
			"output", string(output),
			"path", path)
		return nil, nil, fmt.Errorf("failed to execute klist command: %w", err)
	}
	log.Debug("Klist command completed successfully", "output_size", len(output))

	// Parse the output using the krb_utils package
	ticket, ticketInfo, err := krb_utils.ParseKlistOutput(string(output), path)
	if err != nil {
		log.Error("Failed to parse klist output", "error", err)
		return nil, nil, fmt.Errorf("failed to parse klist output: %w", err)
	}

	log.Info("Successfully retrieved ticket",
		"path", path,
		"principal", ticket.Principal,
		"expires", ticket.ExpirationTime.Format(time.RFC3339))

	return ticket, ticketInfo, nil
}

// GetTicketsFromMetadata retrieves all ticket information from a metadata file
func (c *Client) GetTicketsFromMetadata(metadataPath string) ([]*types.Ticket, []*types.TicketInfo, error) {
	ticketInfoList, err := readMetadataJSONFunc(metadataPath)
	if err != nil {
		log.Error("Failed to read metadata file", "path", metadataPath, "error", err)
		return nil, nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	if len(ticketInfoList) == 0 {
		log.Error("No ticket information found in metadata file", "path", metadataPath)
		return nil, nil, fmt.Errorf("no ticket information found in metadata file: %s", metadataPath)
	}

	var tickets []*types.Ticket
	var validTicketInfos []*types.TicketInfo

	for _, ticketInfo := range ticketInfoList {
		ticket, _, err := c.GetTicket(ticketInfo.KrbFilePath)
		if err != nil {
			log.Warn("Failed to get ticket referenced in metadata",
				"metadata_path", metadataPath,
				"ticket_path", ticketInfo.KrbFilePath,
				"error", err)
			continue // Skip this ticket and try the next one
		}

		tickets = append(tickets, ticket)
		validTicketInfos = append(validTicketInfos, ticketInfo)
	}

	if len(tickets) == 0 {
		log.Error("No valid tickets found in metadata file", "path", metadataPath)
		return nil, nil, fmt.Errorf("no valid tickets found in metadata file: %s", metadataPath)
	}

	return tickets, validTicketInfos, nil
}

// GetAllTicketsFromDirectory retrieves all tickets from metadata files in a directory
func (c *Client) GetAllTicketsFromDirectory(directory string) ([]*types.Ticket, []*types.TicketInfo, error) {
	metadataFiles, err := getMetadataFilePathsFunc(directory)
	if err != nil {
		log.Error("Failed to get metadata files", "directory", directory, "error", err)
		return nil, nil, fmt.Errorf("failed to get metadata files: %w", err)
	}

	var allTickets []*types.Ticket
	var allTicketInfos []*types.TicketInfo

	for _, metadataPath := range metadataFiles {
		tickets, ticketInfos, err := c.GetTicketsFromMetadata(metadataPath)
		if err != nil {
			log.Warn("Failed to get tickets from metadata", "path", metadataPath, "error", err)
			continue // Skip this file and continue with others
		}

		allTickets = append(allTickets, tickets...)
		allTicketInfos = append(allTicketInfos, ticketInfos...)
	}

	if len(allTickets) == 0 {
		log.Error("No valid tickets found in directory", "directory", directory)
		return nil, nil, fmt.Errorf("no valid tickets found in directory: %s", directory)
	}

	return allTickets, allTicketInfos, nil
}

// CreateTicketUsingUsernamePassword creates a Kerberos ticket for user principal
// using the CGO-based krb_utils package instead of shell commands.
func (c *Client) CreateTicketUsingUsernamePassword(domain, username, password string) error {
	return c.CreateTicketUsingUsernamePasswordWithCacheDir(domain, username, password, constants.DefaultUserCacheDir)
}

// CreateTicketUsingUsernamePasswordWithCacheDir creates a Kerberos ticket for user principal
// with a configurable cache directory (useful for testing)
func (c *Client) CreateTicketUsingUsernamePasswordWithCacheDir(domain, username, password, userCacheDir string) error {
	log.Info("Creating Kerberos ticket using CGO", "user principal", username, "domain", domain)

	// Create principal in the same format as before
	principal := fmt.Sprintf("%s@%s", username, strings.ToUpper(domain))

	// Create KinitConfig for krb_utils.GenerateKerberosTicket()
	config := krb_utils.NewKinitConfig(principal, password)
	config.Verify = true

	// Set cache path to the dedicated user-ccache directory
	// This ensures consistent location and avoids conflicts with environment variables
	config.CCachePath = filepath.Join(userCacheDir, fmt.Sprintf("krb5cc_%s", username))

	log.Info("Using dedicated user cache directory",
		"cache_path", config.CCachePath,
		"cache_dir", userCacheDir)

	// Ensure the user cache directory exists with proper permissions
	if err := c.ensureUserCacheDirectory(userCacheDir); err != nil {
		return c.translateKrbUtilsError(err, "prepare user cache directory")
	}

	// Use CGO-based krb_utils instead of shell execution
	err := c.krb5Client.GenerateTicket(config)
	if err != nil {
		log.Error("Kerberos ticket generation failed",
			"error", err,
			"principal", principal)
		return c.translateKrbUtilsError(err, "create Kerberos ticket for user")
	}

	// Set KRB5CCNAME environment variable to point to our custom cache location
	// This ensures that subsequent LDAP operations using GSSAPI can find the ticket
	originalKrb5CCName := c.setKrb5CCNameForUserCache(config.CCachePath)

	// Log the current environment variable value for debugging
	currentKrb5CCName := os.Getenv("KRB5CCNAME")
	log.Info("KRB5CCNAME environment variable status",
		"original_value", originalKrb5CCName,
		"current_value", currentKrb5CCName,
		"cache_path", config.CCachePath)

	// Securely clear the password
	grpc_utils.SecureClearString(&password)

	log.Info("Successfully created Kerberos ticket using CGO", "principal", principal)
	return nil
}

// CreateTicketForGMSA creates a Kerberos ticket for a gMSA account
func (c *Client) CreateTicketForGMSA(ticketInfo *types.TicketInfo) error {
	ctx := context.Background()

	log.Info("Creating Kerberos ticket for gMSA account",
		"domain", ticketInfo.DomainName,
		"service_account", ticketInfo.ServiceAccountName,
		"distinguished_name", ticketInfo.DistinguishedName,
		"krb_file_path", ticketInfo.KrbFilePath)

	// 1. Validate input parameters
	if err := c.validateGMSATicketInfo(ticketInfo); err != nil {
		return err
	}

	// 2. Get base DN and prepare LDAP query parameters
	baseDN, fqdnList, err := c.prepareGMSALDAPParameters(ticketInfo)
	if err != nil {
		return err
	}

	// 3. Find the Distinguished Name if not provided
	if err := c.ensureDistinguishedName(ctx, ticketInfo, baseDN, fqdnList); err != nil {
		// Continue even if we can't find DN - it might be provided in the ticket info
		log.Warn("Could not find distinguished name", "error", err)
	}

	// 4. Find the gMSA password
	password, err := c.findGMSAPassword(ctx, ticketInfo, fqdnList)
	if err != nil {
		return err
	}

	// Ensure we securely clear the password when we're done
	defer func() {
		// Use the SecureClearBytes function to clear the password
		grpc_utils.SecureClearBytes(password)
	}()

	// 5. Create the Kerberos ticket
	return c.createKerberosTicket(ctx, ticketInfo, password)
}

// validateGMSATicketInfo validates the required fields in the ticket info
func (c *Client) validateGMSATicketInfo(ticketInfo *types.TicketInfo) error {
	if ticketInfo.DomainName == "" {
		return fmt.Errorf("domain name is empty")
	}

	if ticketInfo.ServiceAccountName == "" {
		return fmt.Errorf("service account name is empty")
	}

	return nil
}

// prepareGMSALDAPParameters prepares the LDAP parameters needed for querying
func (c *Client) prepareGMSALDAPParameters(ticketInfo *types.TicketInfo) (string, []string, error) {
	baseDN, err := grpc_utils.GetBaseDnFromDomain(ticketInfo.DomainName)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get base DN from domain: %w", err)
	}

	fqdnList, err := getFQDNListFunc(ticketInfo.DomainName)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get FQDN list: %w", err)
	}

	// Check for environment variable override for DN
	if ticketInfo.DistinguishedName == "" && os.Getenv(constants.EnvCFGmsaOU) != "" {
		ticketInfo.DistinguishedName = os.Getenv(constants.EnvCFGmsaOU)
		log.Info("Found Distinguished name as CF_GMSA_OU environment variable")
	}

	return baseDN, fqdnList, nil
}

// ensureDistinguishedName ensures that the ticket info has a distinguished name
func (c *Client) ensureDistinguishedName(ctx context.Context, ticketInfo *types.TicketInfo, baseDN string, fqdnList []string) error {
	if ticketInfo.DistinguishedName != "" {
		return nil // DN already provided
	}

	ldapClient := newLdapClientFunc()

	// Try each FQDN until we find the DN
	for _, fqdn := range fqdnList {
		distinguishedName, err := ldapClient.FindDN(ctx, ticketInfo.ServiceAccountName, baseDN, fqdn)
		if err != nil {
			log.Warn("Failed to find DN for service account",
				"service_account", ticketInfo.ServiceAccountName,
				"fqdn", fqdn,
				"error", err)
			continue
		}

		ticketInfo.DistinguishedName = distinguishedName
		log.Info("Found DN for service account",
			"service_account", ticketInfo.ServiceAccountName,
			"distinguished_name", ticketInfo.DistinguishedName)
		return nil
	}

	return fmt.Errorf("failed to find distinguished name for service account %s", ticketInfo.ServiceAccountName)
}

// findGMSAPassword finds the gMSA password using LDAP queries
func (c *Client) findGMSAPassword(ctx context.Context, ticketInfo *types.TicketInfo, fqdnList []string) ([]byte, error) {
	ldapClient := newLdapClientFunc()

	// Try each FQDN until we find the password
	for _, fqdn := range fqdnList {
		password, err := ldapClient.SearchGMSAPassword(ctx, ticketInfo.DistinguishedName, fqdn, nil)
		if err != nil {
			log.Error("Failed to find gMSA password",
				"service_account", ticketInfo.ServiceAccountName,
				"distinguished_name", ticketInfo.DistinguishedName,
				"fqdn", fqdn,
				"error", err)
			continue
		}

		log.Info("Successfully found gMSA password",
			"service_account", ticketInfo.ServiceAccountName,
			"fqdn", fqdn)

		// We'll securely clear the password after it's used in createKerberosTicket
		return password, nil
	}

	return nil, fmt.Errorf("failed to find gMSA password for service account %s", ticketInfo.ServiceAccountName)
}

// createKerberosTicket creates a Kerberos ticket using CGO-based krb_utils
func (c *Client) createKerberosTicket(ctx context.Context, ticketInfo *types.TicketInfo, password []byte) error {
	principal := fmt.Sprintf("%s$@%s", ticketInfo.ServiceAccountName, strings.ToUpper(ticketInfo.DomainName))

	log.Info("Creating Kerberos ticket for gMSA account using CGO",
		"principal", principal,
		"krb_file_path", ticketInfo.KrbFilePath)

	// Create KinitConfig for GMSA authentication
	config := &krb_utils.KinitConfig{
		Principal:   principal,
		Password:    string(password), // Convert []byte to string
		CCachePath:  ticketInfo.KrbFilePath,
		Forwardable: true,
		Verify:      true,
		Verbose:     false,
	}

	// Use CGO-based krb_utils instead of shell execution
	err := c.krb5Client.GenerateTicket(config)
	if err != nil {
		log.Error("Kerberos ticket generation failed for gMSA account",
			"error", err,
			"principal", principal,
			"krb_file_path", ticketInfo.KrbFilePath)
		return c.translateKrbUtilsError(err, "create Kerberos ticket for gMSA")
	}

	log.Info("Successfully created Kerberos ticket for gMSA account using CGO",
		"principal", principal,
		"krb_file_path", ticketInfo.KrbFilePath)

	return nil
}

// RenewKerberosTicket renews a Kerberos ticket using CGO-based krb_utils
func (c *Client) RenewKerberosTicket(ctx context.Context, krbFilePath string) error {
	log.Info("Renewing Kerberos ticket using CGO", "krb_file_path", krbFilePath)

	// Create KinitConfig for ticket renewal
	config := &krb_utils.KinitConfig{
		CCachePath:  krbFilePath,
		RenewTicket: true, // Enable renewal mode
		Verify:      true,
		Verbose:     false,
	}

	// Use CGO-based krb_utils for renewal instead of shell execution
	err := c.krb5Client.GenerateTicket(config)
	if err != nil {
		log.Error("Kerberos ticket renewal failed",
			"error", err,
			"krb_file_path", krbFilePath)
		return c.translateKrbUtilsError(err, "renew Kerberos ticket")
	}

	log.Info("Successfully renewed Kerberos ticket using CGO", "krb_file_path", krbFilePath)
	return nil
}

// DeleteKerberosLease deletes a Kerberos ticket file and removes its associated metadata
func (c *Client) DeleteKerberosLease(ctx context.Context, krbFilePath string) error {
	log.Info("Deleting Kerberos lease", "krb_file_path", krbFilePath)

	// First, try to destroy the Kerberos ticket using kdestroy
	output, err := c.shellExecutor.Execute(
		ctx,
		"kdestroy",
		"-c", krbFilePath,
	)

	if err != nil {
		log.Warn("Kdestroy command failed, falling back to manual file deletion",
			"error", err,
			"output", string(output),
			"krb_file_path", krbFilePath)
	}

	// Regardless of kdestroy result, attempt to remove the ticket file
	if err := os.Remove(krbFilePath); err != nil && !os.IsNotExist(err) {
		log.Error("Failed to delete Kerberos ticket file",
			"error", err,
			"krb_file_path", krbFilePath)
		return fmt.Errorf("failed to delete Kerberos ticket file: %w", err)
	}

	// Get the metadata file path associated with this ticket
	metadataDir := filepath.Dir(krbFilePath)
	metadataFiles, err := getMetadataFilePathsFunc(metadataDir)
	if err != nil {
		log.Error("Failed to get metadata files",
			"error", err,
			"directory", metadataDir)
		return fmt.Errorf("failed to get metadata files: %w", err)
	}

	// Find and update relevant metadata files
	for _, metadataPath := range metadataFiles {
		if err := c.removeTicketFromMetadata(metadataPath, krbFilePath); err != nil {
			log.Warn("Failed to update metadata file",
				"error", err,
				"metadata_path", metadataPath,
				"krb_file_path", krbFilePath)
			// Continue with other metadata files
		}
	}

	log.Info("Successfully deleted Kerberos lease", "krb_file_path", krbFilePath)
	return nil
}

// removeTicketFromMetadata removes the specified ticket from the metadata file
func (c *Client) removeTicketFromMetadata(metadataPath, krbFilePath string) error {
	ticketInfoList, err := readMetadataJSONFunc(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read metadata file: %w", err)
	}

	// Filter out the ticket we want to remove
	var updatedTicketInfoList []*types.TicketInfo
	for _, ticketInfo := range ticketInfoList {
		if ticketInfo.KrbFilePath != krbFilePath {
			updatedTicketInfoList = append(updatedTicketInfoList, ticketInfo)
		}
	}

	// If no tickets were removed, return early
	if len(updatedTicketInfoList) == len(ticketInfoList) {
		return nil
	}

	// Write the updated list back to the metadata file
	if len(updatedTicketInfoList) == 0 {
		// If no tickets remain, delete the metadata file
		if err := os.Remove(metadataPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("failed to delete empty metadata file: %w", err)
		}
	} else {
		// Otherwise, write the updated list back to the file
		data, err := json.Marshal(updatedTicketInfoList)
		if err != nil {
			return fmt.Errorf("failed to marshal updated ticket info list: %w", err)
		}

		if err := os.WriteFile(metadataPath, data, 0600); err != nil {
			return fmt.Errorf("failed to write updated metadata file: %w", err)
		}
	}

	return nil
}

// CheckAndRenewTicket checks if a ticket needs renewal and renews it if necessary.
// It follows the same logic as the C++ implementation in renewal.cpp.
func (c *Client) CheckAndRenewTicket(ctx context.Context, ticketInfo *types.TicketInfo) error {
	log.Info("Checking ticket for renewal",
		"path", ticketInfo.KrbFilePath,
		"service_account", ticketInfo.ServiceAccountName)

	domainlessUser := ticketInfo.DomainlessUser

	// Agent-managed tickets (created via AddKerberosArnLease or AddNonDomainJoinedKerberosLease)
	// are renewed by the agent via gRPC calls. Skip internal renewal for these.
	if strings.Contains(domainlessUser, "awsdomainlessusersecret") {
		log.Info("Skipping internal renewal for agent-managed ticket",
			"path", ticketInfo.KrbFilePath,
			"domainless_user", domainlessUser)
		return nil
	}

	// Get the ticket information
	ticket, _, err := c.GetTicket(ticketInfo.KrbFilePath)
	if err != nil {
		return fmt.Errorf("failed to get ticket information: %w", err)
	}

	// Check if the ticket is ready for renewal and either:
	// 1. Not a domainless user (empty string), OR
	// 2. A standalone domainless user (config flag enabled)
	isNotDomainlessUser := domainlessUser == ""
	isDomainlessUserStandalone := config_utils.IsRunRenewalNonDomainJoinedEnabled()

	if !isDomainlessUserStandalone && !isNotDomainlessUser {
		log.Info("Skipping renewal for domainless user not created using Domain Join API",
			"path", ticketInfo.KrbFilePath,
			"principal", ticket.Principal,
			"domainless_user", domainlessUser,
			"isDomainlessUserStandalone", isDomainlessUserStandalone)
	} else if !krb_utils.IsTicketReadyForRenewal(ticket) {
		log.Info("Ticket does not need renewal yet",
			"path", ticketInfo.KrbFilePath,
			"principal", ticket.Principal,
			"expiry", ticket.ExpirationTime.Format(time.RFC3339))
	} else {
		log.Info("Ticket is ready for renewal",
			"path", ticketInfo.KrbFilePath,
			"principal", ticket.Principal,
			"expiry", ticket.ExpirationTime.Format(time.RFC3339))

		// Try renewal first using CGO-based implementation
		if err := c.RenewKerberosTicket(ctx, ticketInfo.KrbFilePath); err == nil {
			// Verify the renewed ticket actually has an extended expiry
			renewedTicket, _, err := c.GetTicket(ticketInfo.KrbFilePath)
			if err != nil {
				log.Warn("CGO renewal succeeded but failed to re-read ticket, falling back to recreation", "error", err)
			} else if renewedTicket.ExpirationTime.After(ticket.ExpirationTime) {
				log.Info("Direct renewal of the ticket successful using CGO",
					"new_expiry", renewedTicket.ExpirationTime.Format(time.RFC3339))
				return nil
			} else {
				log.Warn("CGO renewal reported success but ticket expiry was not extended, falling back to recreation",
					"old_expiry", ticket.ExpirationTime.Format(time.RFC3339),
					"current_expiry", renewedTicket.ExpirationTime.Format(time.RFC3339))
			}
		} else {
			log.Warn("Direct renewal failed, attempting ticket recreation", "error", err)
		}

		// If renewal fails, fall back to recreation with retries
		const numRetries = 1
		if err := c.recreateTicketWithRetries(ctx, ticketInfo, numRetries, isDomainlessUserStandalone); err != nil {
			return fmt.Errorf("failed to recreate ticket after %d retries: %w", numRetries+1, err)
		}
	}

	return nil
}

// recreateTicketWithRetries attempts to recreate a Kerberos ticket with the specified number of retries.
func (c *Client) recreateTicketWithRetries(ctx context.Context, ticketInfo *types.TicketInfo, numRetries int, isDomainlessUserStandalone bool) error {
	domainlessUser := ticketInfo.DomainlessUser
	maxRetries := numRetries + 1 // allow at most one extension beyond the original retry count

	for i := 0; i <= numRetries; i++ {
		// Try to recreate the ticket using gMSA password
		if err := c.CreateTicketForGMSA(ticketInfo); err == nil {
			// Success - break out of the retry loop
			log.Info("Direct renewal of the GMSA ticket successful")
			return nil
		} else {
			log.Error("Cannot get gMSA krb ticket using account",
				"service_account", ticketInfo.ServiceAccountName,
				"error", err,
				"attempt", i+1,
				"max_attempts", numRetries+1)

			// Try alternative methods based on user type
			if err := c.tryAlternativeTicketCreation(ctx, ticketInfo, domainlessUser, isDomainlessUserStandalone); err == nil {
				// User/machine ticket recreated — ensure at least one more GMSA attempt
				log.Info("Successfully recreated user principal or machine principal Kerberos ticket, retrying GMSA ticket creation")
				if i == numRetries && numRetries < maxRetries {
					numRetries++ // allow one final GMSA attempt with fresh credentials
				}
				continue
			}
		}
	}

	// If we get here, all retries failed
	return fmt.Errorf("all attempts to recreate ticket failed")
}

// tryAlternativeTicketCreation attempts to create a ticket using alternative methods
// based on the user type (domainless with secret or machine keytab).
func (c *Client) tryAlternativeTicketCreation(ctx context.Context, ticketInfo *types.TicketInfo, domainlessUser string, isDomainlessUserStandalone bool) error {
	// If this is a domainless user with secret support
	if strings.Contains(domainlessUser, "awsdomainlessusersecret") || isDomainlessUserStandalone {
		log.Info("")
		return c.createTicketForDomainlessUser(ctx, ticketInfo, domainlessUser, isDomainlessUserStandalone)
	}

	// For regular users, use machine keytab
	return c.GenerateKrbTicketFromMachineKeytab(ctx, ticketInfo.DomainName)
}

// createTicketForDomainlessUser creates a ticket for a domainless user using AWS Secrets Manager.
func (c *Client) createTicketForDomainlessUser(ctx context.Context, ticketInfo *types.TicketInfo, domainlessUser string, isDomainlessUserStandalone bool) error {
	log.Info("Attempting to recreate Domainless user Kerberos ticket")
	var secretName = ""
	if isDomainlessUserStandalone {
		secretName = config_utils.GetSecretNameFromConf()
		if secretName == "" {
			log.Info("Secret name not found in credentials-fetcher.conf, trying supplied parameter")
		}
	}
	// Check if domainlessUser contains "awsdomainlessusersecret:" and extract the secret name
	if strings.Contains(domainlessUser, "awsdomainlessusersecret:") {
		// Extract the string after "awsdomainlessusersecret:"
		parts := strings.SplitN(domainlessUser, "awsdomainlessusersecret:", 2)
		if len(parts) == 2 {
			secretName = strings.TrimSpace(parts[1])
			log.Info("Found secret name from supplied parameter")
		}
		if secretName == "" {
			log.Info("Secret name not found in supplied parameter, trying ECS config file")
		}
	}
	// Try to get the secret name from the ECS config file
	configSecretName, err := config_utils.GetConfigValue(constants.EnvCFGmsaSecretName)
	if err == nil && configSecretName != "" {
		secretName = configSecretName
		log.Debug("Using secret name from ECS config file", "secretName", secretName, "Overriding all other supplied secret names.")
	} else {
		log.Error("CREDENTIALS_FETCHER_SECRET_NAME_FOR_DOMAINLESS_GMSA variable not found in /etc/ecs/ecs.config or /etc/credentials-fetcher.conf file")
	}

	// Use the GenerateKrbTicketUsingSecretVault function directly
	if secretName != "" {
		if err := c.GenerateKrbTicketUsingSecretVault(ctx, ticketInfo.DomainName, secretName); err != nil {
			log.Error("Cannot get ticket using secret vault",
				"domain", ticketInfo.DomainName,
				"secret_name", secretName,
				"error", err)
			return err
		}
	} else {
		log.Error("Could not find secret name for domainless user",
			"domain", ticketInfo.DomainName, ". Checked in supplied parameter, Environment variable, /etc/ecs/ecs.config, /etc/credentials-fetcher.conf")
		return fmt.Errorf("could not find secret name. Please supply parameter or update /etc/credentials-fetcher.conf ")
	}

	return nil
}

// ProcessAllTicketsForRenewal processes all tickets in the Kerberos directory for renewal
func (c *Client) ProcessAllTicketsForRenewal(ctx context.Context, krbFilesDir string) error {
	log.Info("Processing all tickets for renewal", "directory", krbFilesDir)

	// Get all metadata files in the Kerberos directory
	metadataFiles, err := metadata_utils.GetMetadataFilePaths(krbFilesDir)
	if err != nil {
		return fmt.Errorf("failed to get metadata files: %w", err)
	}

	if len(metadataFiles) == 0 {
		log.Info("No metadata files found, nothing to renew")
		return nil
	}

	log.Info("Found metadata files", "count", len(metadataFiles))

	// Process each metadata file
	for _, metadataPath := range metadataFiles {
		if err := c.processMetadataFileForRenewal(ctx, metadataPath); err != nil {
			log.Error("Failed to process metadata file", "path", metadataPath, "error", err)
			// Continue with other files even if one fails
			continue
		}
	}

	return nil
}

// processMetadataFileForRenewal processes a single metadata file and renews tickets as needed
func (c *Client) processMetadataFileForRenewal(ctx context.Context, metadataPath string) error {
	log.Info("Processing metadata file for renewal", "path", metadataPath)

	// Read ticket info from metadata file
	ticketInfoList, err := metadata_utils.ReadMetadataJSON(metadataPath)
	if err != nil {
		return fmt.Errorf("failed to read metadata file: %w", err)
	}

	if len(ticketInfoList) == 0 {
		log.Warn("No ticket information found in metadata file", "path", metadataPath)
		return nil
	}

	// Check each ticket in the metadata file
	for _, ticketInfo := range ticketInfoList {
		if err := c.CheckAndRenewTicket(ctx, ticketInfo); err != nil {
			log.Error("Failed to check/renew ticket",
				"path", ticketInfo.KrbFilePath,
				"service_account", ticketInfo.ServiceAccountName,
				"error", err)
			// Continue with other tickets even if one fails
			continue
		}
	}

	return nil
}

// GenerateKrbTicketUsingSecretVault generates a Kerberos ticket using credentials from AWS Secrets Manager.
// This function retrieves credentials from AWS Secrets Manager and uses them to create a Kerberos ticket.
func (c *Client) GenerateKrbTicketUsingSecretVault(ctx context.Context, domain, secretName string) error {
	log.Info("Generating Kerberos ticket using Secret Vault",
		"domain", domain,
		"secret_name", secretName)

	// Retrieve the secret from AWS Secrets Manager
	secretMap, err := aws_utils.GetSecretFromSecretsManager(secretName)
	if err != nil {
		log.Error("Failed to retrieve secret from Secrets Manager",
			"secret_name", secretName,
			"error", err)
		return fmt.Errorf("failed to retrieve secret from Secrets Manager: %w", err)
	}

	// Extract username, password, and update distinguished name if available
	username, password, _, _, err := aws_utils.ExtractCredentialsFromSecret(secretMap)
	if err != nil {
		log.Error("Failed to extract credentials from secret",
			"secret_name", secretName,
			"error", err)
		return fmt.Errorf("failed to extract credentials from secret: %w", err)
	}

	// Ensure we securely clear the password when we're done
	defer func() {
		grpc_utils.SecureClearString(&password)
	}()

	// Create the Kerberos ticket using the retrieved credentials
	// This will use the same dedicated user cache directory as CreateTicketUsingUsernamePassword
	err = c.CreateTicketUsingUsernamePassword(domain, username, password)
	if err != nil {
		log.Error("Failed to create Kerberos ticket using credentials from Secret Vault",
			"domain", domain,
			"username", username,
			"error", err)
		return fmt.Errorf("failed to create Kerberos ticket: %w", err)
	}

	log.Info("Successfully generated Kerberos ticket using Secret Vault",
		"domain", domain,
		"username", username)

	return nil
}

// orphanedTicketGracePeriod is how long past the renew_until time before a ticket
// is considered orphaned and eligible for cleanup (7 days).
const orphanedTicketGracePeriod = 7 * 24 * time.Hour

// CleanupOrphanedTickets removes lease directories containing tickets that have
// been expired beyond the grace period. This handles tickets left behind after
// instance reboots where the ECS agent loses track of running tasks.
func (c *Client) CleanupOrphanedTickets(krbFilesDir string) {
	log.Info("Running orphaned ticket cleanup", "directory", krbFilesDir)

	metadataFiles, err := metadata_utils.GetMetadataFilePaths(krbFilesDir)
	if err != nil {
		log.Error("Failed to get metadata files for cleanup", "error", err)
		return
	}

	if len(metadataFiles) == 0 {
		return
	}

	now := time.Now()
	cleaned := 0

	for _, metadataPath := range metadataFiles {
		tickets, _, err := getTicketsFromMetadataFunc(c, metadataPath)
		if err != nil {
			log.Warn("Failed to read tickets for cleanup check", "path", metadataPath, "error", err)
			continue
		}

		// Check if all tickets in this lease are expired beyond grace period
		allExpired := true
		for _, ticket := range tickets {
			if ticket.RenewUntil.IsZero() {
				allExpired = false
				break
			}
			if now.Before(ticket.RenewUntil.Add(orphanedTicketGracePeriod)) {
				allExpired = false
				break
			}
		}

		if allExpired && len(tickets) > 0 {
			// Extract lease directory from metadata path
			leaseDir := filepath.Dir(metadataPath)
			log.Info("Removing orphaned lease", "path", leaseDir,
				"oldest_renew_until", tickets[0].RenewUntil.Format(time.RFC3339))
			if err := os.RemoveAll(leaseDir); err != nil {
				log.Error("Failed to remove orphaned lease directory", "path", leaseDir, "error", err)
			} else {
				cleaned++
			}
		}
	}

	if cleaned > 0 {
		log.Info("Orphaned ticket cleanup complete", "removed", cleaned)
	}
}
