package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.a2z.com/CredentialsFetcherV2/constants"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"

	"golang.a2z.com/CredentialsFetcherV2/internal/auth/kerberos"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/aws_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/krb_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/metadata_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// KerberosArnLeaseInterface extends KerberosArnTicketOperations with Add-specific operations
type KerberosArnLeaseInterface interface {
	KerberosArnTicketOperations

	// AddKerberosArnLease implements the AddKerberosArnLease RPC method
	AddKerberosArnLease(ctx context.Context, req *pb.KerberosArnLeaseRequest) (*pb.CreateKerberosArnLeaseResponse, error)

	// RenewKerberosArnLease implements the RenewKerberosArnLease RPC method
	RenewKerberosArnLease(ctx context.Context, req *pb.RenewKerberosArnLeaseRequest) (*pb.RenewKerberosArnLeaseResponse, error)
}

// KerberosArnTicketOperations defines operations for managing Kerberos tickets using ARNs
type KerberosArnTicketOperations interface {
	// validateRequest validates the Kerberos ARN lease request
	validateRequest(req *pb.KerberosArnLeaseRequest) error

	// createAWSConfig creates an AWS config with the provided credentials
	createAWSConfig(ctx context.Context, req *pb.KerberosArnLeaseRequest) (aws.Config, error)

	// processCredSpecARNs processes the credential spec ARNs and returns the lease ID and ticket info
	processCredSpecARNs(ctx context.Context, req *pb.KerberosArnLeaseRequest, cfg aws.Config) (string, []*types.TicketInfo, []*types.KerberosTicketArnMapping, error)

	// createDummyFiles creates dummy files for test invocations
	createDummyFiles(mountPath string) error

	// processRealCredentialSpec processes a real (non-test) credential spec
	processRealCredentialSpec(ctx context.Context, cfg aws.Config, parts []string, leaseID string) (*types.TicketInfo, *types.KerberosTicketArnMapping, error)

	// createTicketResponseMap creates the response map for the gRPC response
	createTicketResponseMap(ticketArnMappings []*types.KerberosTicketArnMapping) []*pb.KerberosTicketArnResponse

	// createKerberosTickets creates Kerberos tickets for the provided ticket info list
	createKerberosTickets(ctx context.Context, cfg aws.Config, krbTicketInfoList []*types.TicketInfo, leaseID string) error

	// createCredentialCacheFile creates the Kerberos credential cache file
	createCredentialCacheFile(krbTicket *types.TicketInfo, krbCCNameStr string) error

	// cleanupKerberosFiles cleans up Kerberos files on failure
	cleanupKerberosFiles(krbTicketInfoList []*types.TicketInfo)

	// isTestInvocationForUnitTests checks if this is a test invocation
	isTestInvocationForUnitTests(arn string) bool

	// validateCredentials checks if a username, password and domain are valid
	validateCredentials(username, password, domain string) bool
}

// KerberosArnLeaseHandler handles operations related to Kerberos ARN leases
type KerberosArnLeaseHandler struct {
	krbFilesDir   string
	krbClient     *kerberos.Client
	shellExecutor cmdexec.Executor
}

// NewKerberosArnLeaseHandler creates a new KerberosArnLeaseHandler
func NewKerberosArnLeaseHandler(krbFilesDir string, krbClient *kerberos.Client, shellExecutor cmdexec.Executor) *KerberosArnLeaseHandler {
	return &KerberosArnLeaseHandler{
		krbFilesDir:   krbFilesDir,
		krbClient:     krbClient,
		shellExecutor: shellExecutor,
	}
}

// AddKerberosArnLease creates Kerberos tickets using credential spec ARNs
func (h *KerberosArnLeaseHandler) AddKerberosArnLease(ctx context.Context, req *pb.KerberosArnLeaseRequest) (*pb.CreateKerberosArnLeaseResponse, error) {
	log := logger.GetInstance()
	log.Info("Processing AddKerberosArnLease Fargate request")

	// Defer credential clearing to ensure it happens even on early returns
	defer func() {
		grpc_utils.SecureClearString(&req.AccessKeyId)
		grpc_utils.SecureClearString(&req.SecretAccessKey)
		grpc_utils.SecureClearString(&req.SessionToken)
	}()

	// Validate request
	if err := h.validateRequest(req.AccessKeyId, req.SecretAccessKey, req.SessionToken, req.Region); err != nil {
		return nil, err
	}

	if len(req.CredspecArns) == 0 {
		log.Error("No Credspec arn provided")
		return nil, fmt.Errorf("no credspec arn provided")
	}

	// Create AWS config
	cfg, err := h.createAWSConfig(ctx, req.AccessKeyId, req.SecretAccessKey, req.SessionToken, req.Region)
	if err != nil {
		return nil, err
	}

	// Process credential spec ARNs
	leaseID, ticketInfoList, ticketArnMappings, err := h.processCredSpecARNs(ctx, req, cfg)
	if err != nil {
		return nil, err
	}

	// Create response
	response := &pb.CreateKerberosArnLeaseResponse{
		LeaseId: leaseID,
	}

	// If there were no errors and this is not a test, create the Kerberos tickets
	if len(req.CredspecArns) > 0 && !h.isTestInvocationForUnitTests(req.CredspecArns[0]) {
		if err := h.createKerberosTickets(ctx, cfg, ticketInfoList, ticketArnMappings, leaseID); err != nil {
			return nil, err
		}

		// Populate response with ticket information
		response.KrbTicketResponseMap = h.createTicketResponseMap(ticketArnMappings)
	}

	log.Info("Successfully completed AddKerberosArnLease operation")
	return response, nil
}

// validateRequest validates the request parameters
func (h *KerberosArnLeaseHandler) validateRequest(accessKeyId, secretAccessKey, sessionToken, region string) error {
	if accessKeyId == "" || secretAccessKey == "" ||
		sessionToken == "" || region == "" {
		log.Error("Access credentials should not be empty ")
		return fmt.Errorf("access credentials should not be empty ")
	}

	return nil
}

// createAWSConfig creates an AWS config with the provided credentials
func (h *KerberosArnLeaseHandler) createAWSConfig(ctx context.Context, accessKeyId, secretAccessKey, sessionToken, region string) (aws.Config, error) {
	log := logger.GetInstance()

	// Create static credentials provider
	credProvider := credentials.NewStaticCredentialsProvider(
		accessKeyId,
		secretAccessKey,
		sessionToken,
	)

	// Load the configuration with the custom credentials
	cfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(region),
		config.WithCredentialsProvider(credProvider),
	)

	if err != nil {
		log.Error("Failed to create AWS config", "error", err)
		return aws.Config{}, fmt.Errorf("failed to create AWS config: %v", err)
	}

	log.Info("Successfully created AWS config and retrieved credentials")
	return cfg, nil
}

// processCredSpecARNs processes the credential spec ARNs and returns the lease ID and ticket info
func (h *KerberosArnLeaseHandler) processCredSpecARNs(ctx context.Context, req *pb.KerberosArnLeaseRequest, cfg aws.Config) (string, []*types.TicketInfo, []*types.KerberosTicketArnMapping, error) {

	var leaseID string
	krbTicketInfoList := make([]*types.TicketInfo, 0)
	krbTicketArnMappingList := make([]*types.KerberosTicketArnMapping, 0)
	krbTicketDirs := make(map[string]bool)

	for _, credSpecArn := range req.CredspecArns {
		if credSpecArn == "" {
			log.Error("CredentialSpec arn should not be empty")
			return "", nil, nil, fmt.Errorf("credentialspec arn should not be empty")
		}

		// Split the ARN by '#' to get the S3 path and mount path
		parts := strings.Split(credSpecArn, "#")
		if len(parts) != 2 {
			log.Error("CredentialSpec arn is not valid")
			return "", nil, nil, fmt.Errorf("credentialspec arn is not valid")
		}

		// Split the mount path to validate it
		pathParts := strings.Split(parts[1], "/")
		if len(pathParts) != 2 || aws_utils.ContainsInvalidCharactersInCredentialSpec(parts[1]) {
			log.Error("Mount path in CredentialSpec arn is not valid")
			return "", nil, nil, fmt.Errorf("mount path in credential spec arn is not valid")
		}

		// Get lease ID information from the first part of the mount path
		leaseID = pathParts[0]
		// Check if this is a test invocation
		isTest := h.isTestInvocationForUnitTests(parts[0])

		if isTest {
			// Test mode - create dummy files
			log.Info("Test mode - creating dummy files")
			if err := h.createDummyFiles(parts[1]); err != nil {
				return "", nil, nil, fmt.Errorf("failed to create dummy files: %v", err)
			}
		} else {
			// Process real credential spec
			ticketInfo, ticketArn, err := h.processRealCredentialSpec(ctx, cfg, parts, pathParts[0])
			if err != nil {
				return "", nil, nil, err
			}

			// Handle duplicate service accounts
			krbFilesPath := ticketInfo.KrbFilePath
			if _, exists := krbTicketDirs[krbFilesPath]; exists {
				log.Error("Found duplicate mount paths")
				return "", nil, nil, fmt.Errorf("found duplicate mount paths")
			}

			krbTicketDirs[krbFilesPath] = true
			krbTicketInfoList = append(krbTicketInfoList, ticketInfo)
			krbTicketArnMappingList = append(krbTicketArnMappingList, ticketArn)
		}
	}

	return leaseID, krbTicketInfoList, krbTicketArnMappingList, nil
}

// createDummyFiles creates dummy files for test invocations
func (h *KerberosArnLeaseHandler) createDummyFiles(mountPath string) error {

	krbFilesPath := filepath.Join(h.krbFilesDir, mountPath)

	// Create directories
	// #nosec G301
	if err := os.MkdirAll(krbFilesPath, 0755); err != nil {
		log.Error("Failed to create directory ", krbFilesPath, err)
		return err
	}
	log.Info("Created dummy directory at mount path")
	// Create dummy file
	dummyFile := filepath.Join(krbFilesPath, "krb5cc")
	// #nosec G304
	if _, err := os.Create(dummyFile); err != nil {
		log.Error("Failed to create dummy file ", dummyFile, err)
		return err
	}
	log.Info("Created dummy krb5cc at mount path")

	return nil
}

// processRealCredentialSpec processes a real (non-test) credential spec
func (h *KerberosArnLeaseHandler) processRealCredentialSpec(ctx context.Context, cfg aws.Config, parts []string, leaseID string) (*types.TicketInfo, *types.KerberosTicketArnMapping, error) {

	// Check if the S3 object is valid
	isObjectValid, err := aws_utils.CheckFileSizeS3(ctx, cfg, parts[0])
	if err != nil || !isObjectValid {
		log.Error("Invalid object for credentialspec in S3")
		return nil, nil, fmt.Errorf("invalid object for credentialspec in S3")
	}

	// Retrieve credential spec from S3
	credSpecContent, err := aws_utils.RetrieveCredSpecFromS3(ctx, cfg, parts[0])
	if err != nil || credSpecContent == "" {
		log.Error("Credentialspec cannot be retrieved from S3")
		return nil, nil, fmt.Errorf("credentialspec cannot be retrieved from S3")
	}

	// Create and populate the ticket info and mapping structures
	krbTicketInfo := &types.TicketInfo{}
	krbTicketArn := &types.KerberosTicketArnMapping{
		CredentialSpecArn: parts[0],
	}

	// Parse the credential spec
	if err := grpc_utils.ParseCredSpecDomainless(credSpecContent, krbTicketInfo, krbTicketArn); err != nil {
		log.Error("invalid credentialspec fields")
		return nil, nil, fmt.Errorf("invalid credentialspec fields: %w", err)
	}

	// Create the Kerberos files path
	krbFilesPath := filepath.Join(h.krbFilesDir, parts[1])
	krbTicketInfo.KrbFilePath = krbFilesPath
	krbTicketArn.KrbFilePath = krbFilesPath

	return krbTicketInfo, krbTicketArn, nil
}

// createTicketResponseMap creates the response map for the gRPC response
func (h *KerberosArnLeaseHandler) createTicketResponseMap(ticketArnMappings []*types.KerberosTicketArnMapping) []*pb.KerberosTicketArnResponse {
	responseMap := make([]*pb.KerberosTicketArnResponse, 0, len(ticketArnMappings))

	for _, arnMapping := range ticketArnMappings {
		responseMap = append(responseMap, &pb.KerberosTicketArnResponse{
			CredspecArns:             arnMapping.CredentialSpecArn,
			CreatedKerberosFilePaths: arnMapping.KrbFilePath,
		})
	}

	return responseMap
}

// createKerberosTickets creates Kerberos tickets for the provided ticket info list
func (h *KerberosArnLeaseHandler) createKerberosTickets(ctx context.Context, cfg aws.Config, krbTicketInfoList []*types.TicketInfo, krbTicketArnMappings []*types.KerberosTicketArnMapping, leaseID string) error {
	for _, krbTicket := range krbTicketInfoList {
		// Retrieve and validate credentials from Secrets Manager
		secretsArn := ""
		// Find the matching krbTicketMapping where KrbFilePath matches the current krbTicket's KrbFilePath
		for _, mapping := range krbTicketArnMappings {
			if mapping.KrbFilePath == krbTicket.KrbFilePath {
				secretsArn = mapping.CredentialDomainlessUserArn
				log.Info("Found the Secret Manager ARN for this credspec")
				break
			}
		}
		if secretsArn == "" {
			log.Error("Invalid Secrets Manager ARN")
			return fmt.Errorf("invalid secrets manager ARN")
		}

		// Retrieve credentials from Secrets Manager
		secretMap, err := aws_utils.GetSecretFromSecretsManagerWithConfig(ctx, cfg, secretsArn)
		if err != nil {
			log.Error("Failed to retrieve credentials from secrets manager", "error", err)
			return fmt.Errorf("failed to retrieve credentials from secrets manager: %w", err)
		}

		// Extract credentials from the secret
		username, password, domain, distinguishedName, err := aws_utils.ExtractCredentialsFromSecret(secretMap)
		if err != nil {
			log.Error("Failed to extract credentials from secret", "error", err)
			return fmt.Errorf("failed to extract credentials from secret: %w", err)
		}

		// Validate domain and username
		if !aws_utils.IsValidDomain(domain) || aws_utils.ContainsInvalidCharactersInADAccountName(username) {
			log.Error("Invalid domainName/username")
			return fmt.Errorf("invalid domainName/username")
		}

		// Validate credential lengths
		if !h.validateCredentials(username, password, domain) {
			return fmt.Errorf("invalid credentials in secrets manager")
		}

		// Update ticket info with retrieved credentials
		krbTicket.DomainlessUser = username
		krbTicket.DistinguishedName = distinguishedName
		krbTicket.DomainName = domain

		// Create directories for the Kerberos ticket
		// Use the full path instead of just the parent directory
		dirPath := krbTicket.KrbFilePath
		log.Info("Creating directory for Kerberos ticket", "directory", dirPath)
		// #nosec G301
		if err := os.MkdirAll(dirPath, 0755); err != nil { /* #nosec G301 */
			log.Error("Failed to create directory", "path", dirPath, "error", err)
			// Clean up on failure
			h.cleanupKerberosFiles(krbTicketInfoList)
			return fmt.Errorf("failed to create directory %s: %v", dirPath, err)
		}

		// Verify directory was created
		if _, err := os.Stat(dirPath); os.IsNotExist(err) {
			log.Error("Directory was not created despite no error", "path", dirPath)
			h.cleanupKerberosFiles(krbTicketInfoList)
			return fmt.Errorf("directory was not created: %s", dirPath)
		}
		log.Info("Successfully created directory", "path", dirPath)

		// Create the Kerberos credential cache file
		krbCCNameStr := filepath.Join(dirPath, "krb5cc")
		if err := h.createCredentialCacheFile(krbTicket, krbCCNameStr); err != nil {
			h.cleanupKerberosFiles(krbTicketInfoList)
			return err
		}

		// Generate Kerberos ticket using username and password
		if err := h.krbClient.CreateTicketUsingUsernamePassword(
			krbTicket.DomainName,
			krbTicket.DomainlessUser,
			password,
		); err != nil {
			log.Error("Failed to generate Kerberos ticket for domainless user", "error", err)
			h.cleanupKerberosFiles(krbTicketInfoList)
			return fmt.Errorf("failed to generate Kerberos ticket for domainless user: %v", err)
		}

		// Create ticket for gMSA account
		if err := h.krbClient.CreateTicketForGMSA(krbTicket); err != nil {
			log.Error("Failed to create gMSA ticket", "error", err)
			h.cleanupKerberosFiles(krbTicketInfoList)
			return fmt.Errorf("failed to create gMSA ticket: %v", err)
		}

		log.Info("Successfully created Kerberos ticket for", "user", krbTicket.DomainlessUser)

		grpc_utils.SecureClearString(&username)
		grpc_utils.SecureClearString(&password)

	}

	// Write metadata to file
	if err := metadata_utils.WriteMetaDataJSON(krbTicketInfoList, leaseID, h.krbFilesDir); err != nil {
		log.Error("Failed to write metadata", "error", err)

		// Clean up on failure
		h.cleanupKerberosFiles(krbTicketInfoList)
		return fmt.Errorf("failed to write metadata: %v", err)
	}

	return nil
}

// createCredentialCacheFile creates the Kerberos credential cache file
func (h *KerberosArnLeaseHandler) createCredentialCacheFile(krbTicket *types.TicketInfo, krbCCNameStr string) error {

	if _, err := os.Stat(krbCCNameStr); os.IsNotExist(err) { /* #nosec */
		file, err := os.Create(krbCCNameStr) /* #nosec */
		if err != nil {
			log.Error("Failed to create Kerberos credential cache file", "error", err)
			return fmt.Errorf("failed to create Kerberos credential cache file: %v", err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				log.Error("Failed to close Kerberos credential cache file", "error", err)
			}
		}()

		krbTicket.KrbFilePath = krbCCNameStr
		log.Info("Setting krbf file path to krbccname str", krbTicket.KrbFilePath)
	}

	return nil
}

// cleanupKerberosFiles cleans up Kerberos files on failure
func (h *KerberosArnLeaseHandler) cleanupKerberosFiles(krbTicketInfoList []*types.TicketInfo) {
	log := logger.GetInstance()
	log.Info("Cleaning up Kerberos files due to failure")

	for _, krbTicket := range krbTicketInfoList {
		// Use the krb_utils package to clean up
		if err := krb_utils.CleanupKerberosFiles(krbTicket.KrbFilePath); err != nil {
			log.Error("Failed to clean up Kerberos files: %v", err)
		}
	}
}

// Helper functions

// isTestInvocationForUnitTests checks if this is a test invocation
func (h *KerberosArnLeaseHandler) isTestInvocationForUnitTests(arn string) bool {
	return strings.Contains(strings.ToLower(arn), "functionaltestcfspec")
}

// validateCredentials checks if a username, password and domain are valid
func (h *KerberosArnLeaseHandler) validateCredentials(username, password, domain string) bool {
	if username == "" || password == "" || domain == "" ||
		len(username) >= constants.InputCredentialsLength ||
		len(password) >= constants.InputCredentialsLength ||
		len(domain) >= constants.MaxDomainLength {
		log.Error("Domainless AD user credentials is not valid or credentials should not be more than 256 characters")
		return false
	}
	return true
}
