package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/config_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/debug_utils"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/auth/kerberos"
	"golang.a2z.com/CredentialsFetcherV2/internal/auth/ldap"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/krb_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/metadata_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// AddNonDomainJoinedKerberosLeaseInterface extends KerberosTicketOperations with Add-specific operations
type AddNonDomainJoinedKerberosLeaseInterface interface {
	KerberosTicketOperations

	// AddNonDomainJoinedKerberosLease implements the AddNonDomainJoinedKerberosLease RPC method
	AddNonDomainJoinedKerberosLease(ctx context.Context, req *pb.CreateNonDomainJoinedKerberosLeaseRequest) (*pb.CreateNonDomainJoinedKerberosLeaseResponse, error)
}

// KerberosTicketOperations defines operations for managing Kerberos tickets
type KerberosTicketOperations interface {
	// SetupKerberosFileForTicket sets up the Kerberos file for a ticket
	SetupKerberosFileForTicket(ticketInfo *types.TicketInfo) (string, error)

	// GetDistinguishedName gets the distinguished name from ECS config or secrets manager
	GetDistinguishedName(ticketInfo *types.TicketInfo) string

	// CreateKerberosTickets creates Kerberos tickets for each ticket info
	CreateKerberosTickets(ctx context.Context, domain, username, password string, ticketInfoList []*types.TicketInfo) ([]string, error)

	// ValidateCredentials validates the username, password, and domain
	ValidateCredentials(username, password, domain string) error

	// ProcessCredentialSpecs processes credential specs and returns ticket info list
	ProcessCredentialSpecs(credspecContents []string, username, leaseID string) ([]*types.TicketInfo, error)

	// CleanupKerberosFiles removes the Kerberos files if there's an error
	CleanupKerberosFiles(krbFilePath string) error
}

// NonDomainJoinedKerberosHandler handles non-domain joined Kerberos operations
type NonDomainJoinedKerberosHandler struct {
	krbFilesDir     string
	awsSMSecretName string
	krbClient       *kerberos.Client
	ldapClient      *ldap.Client
	shellExecutor   cmdexec.Executor
}

// NewNonDomainJoinedKerberosHandler creates a new handler for non-domain joined Kerberos operations
func NewNonDomainJoinedKerberosHandler(krbFilesDir, awsSMSecretName string, krbClient *kerberos.Client, ldapClient *ldap.Client, shellExecutor cmdexec.Executor) *NonDomainJoinedKerberosHandler {
	return &NonDomainJoinedKerberosHandler{
		krbFilesDir:     krbFilesDir,
		awsSMSecretName: awsSMSecretName,
		krbClient:       krbClient,
		ldapClient:      ldapClient,
		shellExecutor:   shellExecutor,
	}
}

// AddNonDomainJoinedKerberosLease implements the AddNonDomainJoinedKerberosLease RPC method
func (h *NonDomainJoinedKerberosHandler) AddNonDomainJoinedKerberosLease(ctx context.Context, req *pb.CreateNonDomainJoinedKerberosLeaseRequest) (*pb.CreateNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Processing AddNonDomainJoinedKerberosLease request")

	// Defer credential clearing to ensure it happens even on early returns
	defer func() {
		grpc_utils.SecureClearString(&req.Username)
		grpc_utils.SecureClearString(&req.Password)
	}()

	// Validate request
	if err := h.ValidateCredentials(req.Username, req.Password, req.Domain); err != nil {
		return nil, err
	}

	if len(req.CredspecContents) == 0 {
		log.Error("No credential specs provided in request")
		return nil, fmt.Errorf("at least one credential spec is required")
	}

	// Generate a lease ID
	leaseID, err := grpc_utils.GenerateLeaseID()
	if err != nil {
		log.Error("Failed to generate lease ID", "error", err)
		return nil, fmt.Errorf("failed to generate lease ID: %v", err)
	}

	// Process credential specs
	ticketInfoList, err := h.ProcessCredentialSpecs(req.CredspecContents, req.Username, leaseID)
	if err != nil {
		return nil, err
	}

	// Create Kerberos tickets
	createdKrbFilePaths, err := h.CreateKerberosTickets(ctx, req.Domain, req.Username, req.Password, ticketInfoList)
	if err != nil {
		return nil, err
	}

	// Write metadata
	if err := metadata_utils.WriteMetaDataJSON(ticketInfoList, leaseID, h.krbFilesDir); err != nil {
		log.Error("Failed to write metadata JSON", "error", err)
		// Clean up all created Kerberos files if there's an error
		for _, krbFilePath := range createdKrbFilePaths {
			if cleanupErr := h.CleanupKerberosFiles(krbFilePath); cleanupErr != nil {
				log.Error("Failed to clean up Kerberos files", "error", cleanupErr)
			}
		}
		return nil, fmt.Errorf("failed to write metadata JSON: %v", err)
	}

	log.Info("Created New NonDomainJoinedKerberosLease", "Lease ID: ", leaseID, "Mount Paths: ", createdKrbFilePaths)

	// Return the response with lease ID and created Kerberos file paths
	return &pb.CreateNonDomainJoinedKerberosLeaseResponse{
		LeaseId:                  leaseID,
		CreatedKerberosFilePaths: createdKrbFilePaths,
	}, nil
}

// ValidateCredentials validates the username, password, and domain
func (h *NonDomainJoinedKerberosHandler) ValidateCredentials(username, password, domain string) error {
	// Validate required parameters
	if username == "" || password == "" || domain == "" {
		log.Error("Missing required parameters in request")
		return fmt.Errorf("username, password, and domain are required")
	}

	// Validate credential lengths
	if err := grpc_utils.ValidateCredentialLength(username, password, domain); err != nil {
		log.Error("Invalid credential length", "error", err)
		return fmt.Errorf("invalid credential length: %v", err)
	}

	// Validate username
	if err := grpc_utils.ValidateAccountName(username); err != nil {
		log.Error("Invalid username", "error", err)
		return fmt.Errorf("invalid username: %v", err)
	}

	// Validate domain
	if err := grpc_utils.ValidateDomain(domain); err != nil {
		log.Error("Invalid domain", "error", err)
		return fmt.Errorf("invalid domain: %v", err)
	}

	return nil
}

// ProcessCredentialSpecs processes the credential specs and returns a list of ticket info objects
func (h *NonDomainJoinedKerberosHandler) ProcessCredentialSpecs(credspecContents []string, username, leaseID string) ([]*types.TicketInfo, error) {
	ticketInfoList, err := krb_utils.ProcessCredentialSpecs(credspecContents, username, leaseID, h.krbFilesDir)
	if err != nil {
		return nil, err
	}

	// Check if any ticket info has an empty CredentialArn, which indicates domain-joined environment
	// but non-domain-joined API was invoked
	for _, ticketInfo := range ticketInfoList {
		if ticketInfo.CredentialArn == "" {
			log.Error("Domain-joined credential spec or environment detected but non-domain-joined API was invoked",
				"service_account", ticketInfo.ServiceAccountName)
			return nil, fmt.Errorf("domain-joined credential spec or environment detected but non-domain-joined API was invoked for service account %s. Please use the domain-joined API instead", ticketInfo.ServiceAccountName)
		}
	}

	return ticketInfoList, nil
}

// CreateKerberosTickets creates Kerberos tickets for each ticket info
func (h *NonDomainJoinedKerberosHandler) CreateKerberosTickets(ctx context.Context, domain, username, password string, ticketInfoList []*types.TicketInfo) ([]string, error) {
	var createdKrbFilePaths []string

	// Generate krb ticket using username and password
	err := h.krbClient.CreateTicketUsingUsernamePassword(domain, username, password)
	if err != nil {
		log.Error("Failed to create Kerberos ticket for domainless user", "error", err)
		return nil, fmt.Errorf("failed to create Kerberos ticket for domainless user: %v", err)
	}

	for _, ticketInfo := range ticketInfoList {
		krbFilePath, err := h.SetupKerberosFileForTicket(ticketInfo)
		if err == nil {
			err = debug_utils.SimulateDebugError(debug_utils.SimulateSetupKerberosFile)
		}
		if err != nil {
			for _, path := range createdKrbFilePaths {
				if cleanupErr := h.CleanupKerberosFiles(path); cleanupErr != nil {
					log.Error("Failed to clean up Kerberos files during error handling",
						"path", path, "error", cleanupErr)
				}
			}
			return nil, err
		}

		// Get distinguished name (non-fatal: empty string is acceptable,
		// downstream LDAP lookup in CreateTicketForGMSA will resolve it)
		distinguishedName := h.GetDistinguishedName(ticketInfo)
		if distinguishedName == "" {
			log.Warn("Distinguished name lookup returned empty, will rely on downstream LDAP resolution",
				"service_account", ticketInfo.ServiceAccountName)
		}

		// Update ticketInfo with the distinguished name
		ticketInfo.DistinguishedName = distinguishedName
		log.Info("Set distinguished name for ticket", "distinguished_name", distinguishedName)

		// Create krb ticket for this gmsa account using the ticketInfo
		err = h.krbClient.CreateTicketForGMSA(ticketInfo)
		if err == nil {
			err = debug_utils.SimulateDebugError(debug_utils.SimulateCreateTicketGMSA)
		}
		if err != nil {
			log.Error("Failed to create Kerberos ticket for gMSA account", "error", err)
			if cleanupErr := h.CleanupKerberosFiles(krbFilePath); cleanupErr != nil {
				log.Error("Failed to clean up Kerberos files during error handling",
					"path", krbFilePath, "error", cleanupErr)
			}
			for _, path := range createdKrbFilePaths {
				if cleanupErr := h.CleanupKerberosFiles(path); cleanupErr != nil {
					log.Error("Failed to clean up Kerberos files during error handling",
						"path", path, "error", cleanupErr)
				}
			}
			return nil, fmt.Errorf("failed to create Kerberos ticket for gMSA account: %v", err)
		}

		// Add the created Kerberos file path to the list
		createdKrbFilePaths = append(createdKrbFilePaths, krbFilePath)
	}

	return createdKrbFilePaths, nil
}

// SetupKerberosFileForTicket sets up the Kerberos file for a ticket
func (h *NonDomainJoinedKerberosHandler) SetupKerberosFileForTicket(ticketInfo *types.TicketInfo) (string, error) {
	krbDirectoryPath := ticketInfo.KrbFilePath

	// Check if krb file path directory already exists, otherwise create directory
	if _, err := os.Stat(krbDirectoryPath); os.IsNotExist(err) {
		log.Info("Creating directory for Kerberos ticket", "path", krbDirectoryPath)
		// #nosec G301
		if err := os.MkdirAll(krbDirectoryPath, 0755); err != nil {
			log.Error("Failed to create directory for Kerberos ticket", "error", err)
			return "", fmt.Errorf("failed to create directory for Kerberos ticket: %v", err)
		}
	} else {
		log.Info("Directory already exists", "path", krbDirectoryPath)
	}

	// Create krb ticket file path by appending krb5cc
	krbTicketFilePath := filepath.Join(krbDirectoryPath, "krb5cc")

	// Create a file at krb5cc if it doesn't exist
	if _, err := os.Stat(krbTicketFilePath); os.IsNotExist(err) {
		file, err := os.Create(krbTicketFilePath) // #nosec G304
		if err != nil {
			log.Error("Failed to create Kerberos credential cache file", "error", err)
			return "", fmt.Errorf("failed to create Kerberos credential cache file: %v", err)
		}
		err = file.Close()
		if err != nil {
			return "", err
		}

		// Update the krb file path in the ticket info
		ticketInfo.KrbFilePath = krbTicketFilePath
	}

	// ECS Agent expects a directory that contains ticket
	return krbDirectoryPath, nil
}

// GetDistinguishedName attempts to retrieve the distinguished name from ECS config
// or secrets manager. It never returns an error — when both sources fail it returns
// an empty string, allowing downstream code (ensureDistinguishedName in krb_client)
// to resolve it via LDAP.
func (h *NonDomainJoinedKerberosHandler) GetDistinguishedName(ticketInfo *types.TicketInfo) string {
	// Get distinguished name from ECS config
	distinguishedName, ecsErr := config_utils.RetrieveVariableFromECSConfig(constants.EnvCFDistinguishedName)
	if ecsErr != nil {
		log.Warn("Could not retrieve distinguished name from ECS config, will try other sources", "error", ecsErr)
		distinguishedName = ""
	}

	if distinguishedName == "" {
		// Get distinguished name from secrets manager if not found in ECS config
		secretDn, secretErr := grpc_utils.GetBaseDnFromSecret(ticketInfo.CredentialArn)
		if secretErr != nil {
			log.Warn("Could not get distinguished name from secret", "error", secretErr)
		} else if secretDn != "" {
			distinguishedName = secretDn
			log.Info("Retrieved distinguished name from secrets manager", "distinguished_name", distinguishedName)
		}
	}

	if distinguishedName == "" {
		log.Warn("Distinguished name not found in ECS config or secrets manager, downstream LDAP lookup will be attempted")
	}

	return distinguishedName
}

// CleanupKerberosFiles removes the Kerberos files if there's an error
func (h *NonDomainJoinedKerberosHandler) CleanupKerberosFiles(krbFilePath string) error {
	return krb_utils.CleanupKerberosFiles(krbFilePath)
}
