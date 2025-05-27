package kerberos

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/internal/auth/ldap"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
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
)

type Client struct {
	shellExecutor cmdexec.Executor
}

func NewClient() *Client {
	return &Client{
		shellExecutor: cmdexec.NewExecutor(),
	}
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
func (c *Client) CreateTicketUsingUsernamePassword(domain, username, password string) error {
	log.Info("Creating Kerberos ticket", "user principal", username, "domain", domain)

	// Build and execute the kinit command to create a Kerberos ticket
	ctx := context.Background()

	// Example command: kinit standarduser01@EXAMPLE.COM
	principal := fmt.Sprintf("%s@%s", username, strings.ToUpper(domain))

	// Use ExecuteWithStdin to pipe the password to kinit without setting environment variables
	// Execute: kinit username@domain
	// and pipe in the password
	output, err := c.shellExecutor.ExecuteWithStdin(
		ctx,
		"kinit",
		[]byte(password+"\n"), // Add newline to simulate pressing Enter
		principal,
	)

	if err != nil {
		log.Error("Kinit command failed",
			"error", err,
			"output", string(output),
			"principal", principal)
		return fmt.Errorf("failed to execute kinit command: %v: %s", err, string(output))
	}

	log.Info("Successfully created Kerberos ticket", "principal", principal)
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
	if ticketInfo.DistinguishedName == "" && os.Getenv("CF_GMSA_OU") != "" {
		ticketInfo.DistinguishedName = os.Getenv("CF_GMSA_OU")
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

		return password, nil
	}

	return nil, fmt.Errorf("failed to find gMSA password for service account %s", ticketInfo.ServiceAccountName)
}

// createKerberosTicket creates a Kerberos ticket using kinit
func (c *Client) createKerberosTicket(ctx context.Context, ticketInfo *types.TicketInfo, password []byte) error {
	principal := fmt.Sprintf("%s@%s", ticketInfo.ServiceAccountName, strings.ToUpper(ticketInfo.DomainName))

	log.Info("Creating Kerberos ticket for gMSA account",
		"principal", principal,
		"krb_file_path", ticketInfo.KrbFilePath)

	output, err := c.shellExecutor.ExecuteWithStdin(
		ctx,
		"kinit",
		password,
		"-c", ticketInfo.KrbFilePath,
		"-V",
		principal,
	)

	if err != nil {
		log.Error("Kinit command failed for gMSA account",
			"error", err,
			"output", string(output),
			"principal", principal)
		return fmt.Errorf("failed to execute kinit command: %v: %s", err, string(output))
	}

	log.Info("Successfully created Kerberos ticket for gMSA account",
		"principal", principal,
		"krb_file_path", ticketInfo.KrbFilePath)

	return nil
}

// CreateTicketForServiceAccount creates a Kerberos ticket for a service account
func (c *Client) CreateTicketForServiceAccount(ctx context.Context, domain, username, password, krbFilePath string) error {
	log.Info("Creating Kerberos ticket for service account",
		"domain", domain,
		"username", username,
		"krb_file_path", krbFilePath)

	// Build and execute the kinit command to create a Kerberos ticket
	principal := fmt.Sprintf("%s@%s", username, strings.ToUpper(domain))

	// Use ExecuteWithStdin to pipe the password to kinit with command-line arguments
	output, err := c.shellExecutor.ExecuteWithStdin(
		ctx,
		"kinit",
		[]byte(password+"\n"), // Add newline to simulate pressing Enter
		"-c", krbFilePath,
		principal,
	)

	if err != nil {
		log.Error("Kinit command failed for service account",
			"error", err,
			"output", string(output),
			"principal", principal)
		return fmt.Errorf("failed to execute kinit command: %v: %s", err, string(output))
	}

	log.Info("Successfully created Kerberos ticket for service account",
		"principal", principal,
		"krb_file_path", krbFilePath)

	return nil
}

// RenewKerberosTicket renews a Kerberos ticket using kinit -R
func (c *Client) RenewKerberosTicket(ctx context.Context, krbFilePath string) error {
	log.Info("Renewing Kerberos ticket", "krb_file_path", krbFilePath)

	// Execute kinit -R to renew the ticket
	output, err := c.shellExecutor.Execute(
		ctx,
		"kinit",
		"-R",
		"-c", krbFilePath,
	)

	if err != nil {
		log.Error("Kinit renewal command failed",
			"error", err,
			"output", string(output),
			"krb_file_path", krbFilePath)
		return fmt.Errorf("failed to execute kinit renewal command: %v: %s", err, string(output))
	}

	log.Info("Successfully renewed Kerberos ticket", "krb_file_path", krbFilePath)
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
