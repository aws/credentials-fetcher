package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.a2z.com/CredentialsFetcherV2/internal/auth/kerberos"

	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/krb_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/metadata_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// DomainJoinedKerberosLeaseInterface extends DomainJoinedKerberosTicketOperations with Add-specific operations
type DomainJoinedKerberosLeaseInterface interface {
	DomainJoinedKerberosTicketOperations

	// AddKerberosLease implements the AddKerberosLease RPC method
	AddKerberosLease(ctx context.Context, req *pb.CreateKerberosLeaseRequest) (*pb.CreateKerberosLeaseResponse, error)
}

// DomainJoinedKerberosTicketOperations defines operations for managing Kerberos tickets in domain-joined mode
type DomainJoinedKerberosTicketOperations interface {
	// SetupKerberosFileForTicket sets up the Kerberos file for a ticket
	SetupKerberosFileForTicket(ticketInfo *types.TicketInfo) (string, error)

	// CreateKerberosTickets creates Kerberos tickets for each ticket info in domain-joined mode
	CreateKerberosTickets(ctx context.Context, ticketInfoList []*types.TicketInfo) ([]string, error)

	// ProcessCredentialSpecs processes credential specs and returns ticket info list
	ProcessCredentialSpecs(credspecContents []string, leaseID string) ([]*types.TicketInfo, error)

	// CleanupKerberosFiles removes the Kerberos files if there's an error
	CleanupKerberosFiles(krbFilePath string) error

	// CreateTicketForGMSA creates a Kerberos ticket for a gMSA account in domain-joined mode
	CreateTicketForGMSA(ctx context.Context, ticketInfo *types.TicketInfo) error

	// GenerateKrbTicketUsingSecretVault generates a Kerberos ticket using credentials from AWS Secrets Manager
	GenerateKrbTicketUsingSecretVault(domain, secretName string) error

	// GenerateKrbTicketFromMachineKeytab generates a Kerberos ticket using the machine's keytab file
	GenerateKrbTicketFromMachineKeytab(ctx context.Context, domain string) error
}

// DomainJoinedKerberosLeaseHandler handles domain-joined Kerberos operations
type DomainJoinedKerberosLeaseHandler struct {
	krbFilesDir     string
	awsSMSecretName string
	krbClient       *kerberos.Client
}

// NewDomainJoinedKerberosLeaseHandler creates a new handler for domain-joined Kerberos operations
func NewDomainJoinedKerberosLeaseHandler(krbFilesDir, awsSMSecretName string, krbClient *kerberos.Client) *DomainJoinedKerberosLeaseHandler {
	return &DomainJoinedKerberosLeaseHandler{
		krbFilesDir:     krbFilesDir,
		awsSMSecretName: awsSMSecretName,
		krbClient:       krbClient,
	}
}

// AddKerberosLease implements the AddKerberosLease RPC method for domain-joined instances
func (h *DomainJoinedKerberosLeaseHandler) AddKerberosLease(ctx context.Context, req *pb.CreateKerberosLeaseRequest) (*pb.CreateKerberosLeaseResponse, error) {
	log.Info("Processing AdKerberosLease DomainJoined request")

	// Validate request
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
	ticketInfoList, err := h.ProcessCredentialSpecs(req.CredspecContents, leaseID)
	if err != nil {
		return nil, err
	}

	// Create Kerberos tickets
	createdKrbFilePaths, err := h.CreateKerberosTickets(ctx, ticketInfoList)
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

	// Return the response with lease ID and created Kerberos file paths
	return &pb.CreateKerberosLeaseResponse{
		LeaseId:                  leaseID,
		CreatedKerberosFilePaths: createdKrbFilePaths,
	}, nil
}

// ProcessCredentialSpecs processes credential specs and returns ticket info list
func (h *DomainJoinedKerberosLeaseHandler) ProcessCredentialSpecs(credspecContents []string, leaseID string) ([]*types.TicketInfo, error) {
	return krb_utils.ProcessCredentialSpecs(credspecContents, "", leaseID, h.krbFilesDir)
}

// CreateKerberosTickets creates Kerberos tickets for each ticket info in domain-joined mode
func (h *DomainJoinedKerberosLeaseHandler) CreateKerberosTickets(ctx context.Context, ticketInfoList []*types.TicketInfo) ([]string, error) {
	var createdKrbFilePaths []string

	// First, get machine tickets for all service accounts
	for _, ticketInfo := range ticketInfoList {
		var err error
		if h.awsSMSecretName != "" {
			// Use AWS Secrets Manager to get credentials
			log.Info("Getting machine ticket using AWS Secrets Manager",
				"domain", ticketInfo.DomainName,
				"secret_name", h.awsSMSecretName)

			err = h.GenerateKrbTicketUsingSecretVault(ticketInfo.DomainName, h.awsSMSecretName)
			if err != nil {
				log.Error("Failed to generate Kerberos ticket using secret vault",
					"domain", ticketInfo.DomainName,
					"error", err)
				return nil, fmt.Errorf("failed to generate Kerberos ticket using secret vault: %v", err)
			}

			// Update the ticket info with the domainless user information
			ticketInfo.DomainlessUser = "awsdomainlessusersecret:" + h.awsSMSecretName
		} else {
			// Use the machine's keytab file
			log.Info("Getting machine ticket using machine keytab", "domain", ticketInfo.DomainName)

			err = h.krbClient.GenerateKrbTicketFromMachineKeytab(ctx, ticketInfo.DomainName)
			if err != nil {
				log.Error("Failed to generate Kerberos ticket from machine keytab",
					"domain", ticketInfo.DomainName,
					"error", err)
				return nil, fmt.Errorf("failed to generate Kerberos ticket from machine keytab: %v", err)
			}
		}

		// Now proceed with creating tickets for each gMSA account
		krbFilePath, err := h.SetupKerberosFileForTicket(ticketInfo)
		if err != nil {
			// Clean up any created files on error
			for _, path := range createdKrbFilePaths {
				err := h.CleanupKerberosFiles(path) // #nosec G104
				if err != nil {
					return nil, err
				}
			}
			return nil, err
		}

		// Create krb ticket for this gmsa account using the ticketInfo
		err = h.CreateTicketForGMSA(ctx, ticketInfo)
		if err != nil {
			log.Error("Failed to create Kerberos ticket for gMSA account", "error", err)
			// Clean up Kerberos files if there's an error
			err := h.CleanupKerberosFiles(krbFilePath) // #nosec G104
			if err != nil {
				return nil, err
			}
			for _, path := range createdKrbFilePaths {
				err := h.CleanupKerberosFiles(path) // #nosec G104
				if err != nil {
					return nil, err
				}
			}
			return nil, fmt.Errorf("failed to create Kerberos ticket for gMSA account: %v", err)
		}

		// Add the created Kerberos file path to the list
		createdKrbFilePaths = append(createdKrbFilePaths, krbFilePath)
	}

	return createdKrbFilePaths, nil
}

// GenerateKrbTicketUsingSecretVault generates a Kerberos ticket using credentials from AWS Secrets Manager
func (h *DomainJoinedKerberosLeaseHandler) GenerateKrbTicketUsingSecretVault(domain, secretName string) error {
	// Use the client's implementation directly
	return h.krbClient.GenerateKrbTicketUsingSecretVault(context.Background(), domain, secretName)
}

// GenerateKrbTicketFromMachineKeytab generates a Kerberos ticket using the machine's keytab file
func (h *DomainJoinedKerberosLeaseHandler) GenerateKrbTicketFromMachineKeytab(ctx context.Context, domain string) error {
	return h.krbClient.GenerateKrbTicketFromMachineKeytab(ctx, domain)
}

// SetupKerberosFileForTicket sets up the Kerberos file for a ticket
func (h *DomainJoinedKerberosLeaseHandler) SetupKerberosFileForTicket(ticketInfo *types.TicketInfo) (string, error) {
	krbFilePath := ticketInfo.KrbFilePath

	// Check if krb file path directory already exists, otherwise create directory
	if _, err := os.Stat(krbFilePath); os.IsNotExist(err) {
		log.Info("Creating directory for Kerberos ticket", "path", krbFilePath)
		if err := os.MkdirAll(krbFilePath, 0750); err != nil {
			log.Error("Failed to create directory for Kerberos ticket", "error", err)
			return "", fmt.Errorf("failed to create directory for Kerberos ticket: %v", err)
		}
	} else {
		log.Info("Directory already exists", "path", krbFilePath)
	}

	// Create krbccname str by appending krb5cc
	krbCCNameStr := filepath.Join(krbFilePath, "krb5cc")

	// Create a file at krb5cc if it doesn't exist
	if _, err := os.Stat(krbCCNameStr); os.IsNotExist(err) {
		file, err := os.Create(krbCCNameStr) // #nosec G304
		if err != nil {
			log.Error("Failed to create Kerberos credential cache file", "error", err)
			return "", fmt.Errorf("failed to create Kerberos credential cache file: %v", err)
		}
		if err := file.Close(); err != nil {
			log.Warn("Failed to close file", "error", err)
		}

		// Update the krb file path in the ticket info
		ticketInfo.KrbFilePath = krbCCNameStr
	}

	return krbCCNameStr, nil
}

// CreateTicketForGMSA creates a Kerberos ticket for a gMSA account in domain-joined mode
func (h *DomainJoinedKerberosLeaseHandler) CreateTicketForGMSA(ctx context.Context, ticketInfo *types.TicketInfo) error {
	// In domain-joined mode, we would use the computer account to get a ticket for the gMSA
	log.Info("Creating Kerberos ticket for gMSA account in domain-joined mode",
		"service_account", ticketInfo.ServiceAccountName,
		"domain", ticketInfo.DomainName,
		"krb_file_path", ticketInfo.KrbFilePath)

	return h.krbClient.CreateTicketForGMSA(ticketInfo)

}

// CleanupKerberosFiles removes the Kerberos files if there's an error
func (h *DomainJoinedKerberosLeaseHandler) CleanupKerberosFiles(krbFilePath string) error {
	return krb_utils.CleanupKerberosFiles(krbFilePath)
}
