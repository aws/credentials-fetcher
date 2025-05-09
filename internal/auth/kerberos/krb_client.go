package kerberos

import (
	"context"
	"fmt"
	"os"
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

var (
	readMetadataJSONFunc     = metadata_utils.ReadMetadataJSON
	getMetadataFilePathsFunc = metadata_utils.GetMetadataFilePaths
	krbCCName                = "/tmp/krb5cc_credentialsfetcher"
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

	if ticketInfo.DomainName == "" {
		return fmt.Errorf("domain name is empty")
	}

	if ticketInfo.ServiceAccountName == "" {
		return fmt.Errorf("service account name is empty")
	}
	var baseDN = ""
	baseDN, err := grpc_utils.GetBaseDnFromDomain(ticketInfo.DomainName)
	if err != nil {
		return fmt.Errorf("failed to get base DN from domain: %w", err)
	}

	if ticketInfo.DistinguishedName == "" && os.Getenv("CF_GMSA_OU") != "" {
		ticketInfo.DistinguishedName = os.Getenv("CF_GMSA_OU")
	}

	fqdnListResult, err := grpc_utils.GetFQDNList(ticketInfo.DomainName)
	if err != nil {
		return fmt.Errorf("failed to get FQDN list: %w", err)
	}

	ldapClient := ldap.NewClient()
	var password []byte
	var passwordFound bool

	for _, fqdn := range fqdnListResult {
		if ticketInfo.DistinguishedName == "" {
			// execute ldapsearch to find DN
			distinguishedNameResult, err := ldapClient.FindDN(ctx, ticketInfo.ServiceAccountName, baseDN, fqdn)
			if err != nil {
				log.Warn("Failed to find DN for service account",
					"service_account", ticketInfo.ServiceAccountName,
					"error", err)
			} else {
				ticketInfo.DistinguishedName = distinguishedNameResult
				log.Info("Found DN for service account",
					"service_account", ticketInfo.ServiceAccountName,
					"distinguished_name", ticketInfo.DistinguishedName)
			}
		}

		// Execute ldapsearch to find the password
		password, err = ldapClient.SearchGMSAPassword(ctx, ticketInfo.DistinguishedName, fqdn, nil)
		if err != nil {
			log.Error("Failed to find gMSA password",
				"service_account", ticketInfo.ServiceAccountName,
				"distinguished_name", ticketInfo.DistinguishedName,
				"fqdn", fqdn,
				"error", err)
			continue // Try with next FQDN
		}

		// Successfully found the password
		log.Info("Successfully found gMSA password",
			"service_account", ticketInfo.ServiceAccountName,
			"fqdn", fqdn)

		passwordFound = true
		break // Successfully found the password, no need to try other FQDNs
	}

	if !passwordFound || len(password) == 0 {
		log.Error("Failed to find gMSA password for any FQDN",
			"service_account", ticketInfo.ServiceAccountName)
		return fmt.Errorf("failed to find gMSA password for service account %s", ticketInfo.ServiceAccountName)
	}

	// Now run kinit command with the found password
	principal := fmt.Sprintf("%s@%s", ticketInfo.ServiceAccountName, strings.ToUpper(ticketInfo.DomainName))

	log.Info("Creating Kerberos ticket for gMSA account",
		"principal", principal,
		"krb_file_path", ticketInfo.KrbFilePath)

	// Use ExecuteWithStdin to pipe the password to kinit with command-line arguments
	output, err := c.shellExecutor.ExecuteWithStdin(
		ctx,
		"kinit",
		password, // Use the found password
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
