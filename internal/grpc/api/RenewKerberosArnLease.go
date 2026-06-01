package api

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/aws_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/metadata_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// RenewKerberosArnLease renews Kerberos tickets using AWS credentials
func (h *KerberosArnLeaseHandler) RenewKerberosArnLease(ctx context.Context, req *pb.RenewKerberosArnLeaseRequest) (*pb.RenewKerberosArnLeaseResponse, error) {
	h.renewMu.Lock()
	defer h.renewMu.Unlock()

	log := logger.GetInstance()
	log.Info("Processing RenewKerberosArnLease Fargate request")

	// Defer credential clearing to ensure it happens even on early returns
	defer func() {
		grpc_utils.SecureClearString(&req.AccessKeyId)
		grpc_utils.SecureClearString(&req.SecretAccessKey)
		grpc_utils.SecureClearString(&req.SessionToken)
	}()

	// Create response object
	response := &pb.RenewKerberosArnLeaseResponse{}

	if err := h.validateRequest(req.AccessKeyId, req.SecretAccessKey, req.SessionToken, req.Region); err != nil {
		response.Status = "failed"
		return response, err
	}

	// Create AWS config
	cfg, err := h.createAWSConfig(ctx, req.AccessKeyId, req.SecretAccessKey, req.SessionToken, req.Region)
	if err != nil {
		response.Status = "failed"
		return response, err
	}

	// Get and process metadata files with a timeout to prevent CGO/LDAP hangs.
	// If the operation hangs beyond 30 seconds, wait for it to finish, then retry once.
	const maxAttempts = 2
	const renewTimeout = 30 * time.Second

	type result struct{ err error }
	var prevDone <-chan result
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		// Wait for previous attempt's goroutine to avoid concurrent processMetadataFiles
		if prevDone != nil {
			select {
			case <-prevDone:
			case <-time.After(2 * renewTimeout): // Bound wait to prevent indefinite blocking
				log.Warn("Previous renewal goroutine still running after extended timeout")
			case <-ctx.Done():
				response.Status = "failed"
				return response, ctx.Err()
			}
		}

		renewCtx, cancel := context.WithTimeout(ctx, renewTimeout)
		done := make(chan result, 1)
		go func() {
			done <- result{h.processMetadataFiles(renewCtx, cfg)}
		}()

		select {
		case r := <-done:
			cancel()
			if r.err != nil {
				response.Status = "failed"
				return response, r.err
			}
			// Success
			goto renewed
		case <-renewCtx.Done():
			cancel()
			prevDone = done // track so next iteration waits
			log.Warn("RenewKerberosArnLease timed out, retrying",
				"attempt", attempt,
				"max_attempts", maxAttempts)
		}
	}

	// All attempts timed out
	log.Error("RenewKerberosArnLease failed after all retry attempts")
	response.Status = "failed"
	return response, fmt.Errorf("renewal timed out after %d attempts", maxAttempts)

renewed:

	response.Status = "successful"
	return response, nil
}

// processMetadataFiles retrieves and processes all metadata files for renewal
func (h *KerberosArnLeaseHandler) processMetadataFiles(ctx context.Context, cfg aws.Config) error {
	log := logger.GetInstance()

	// Get all metadata files in the Kerberos directory
	metadataFiles, err := metadata_utils.GetMetadataFilePaths(h.krbFilesDir)
	if err != nil {
		log.Error("Failed to get metadata files", "error", err)
		return fmt.Errorf("failed to get metadata files: %w", err)
	}

	if len(metadataFiles) == 0 {
		log.Info("No metadata files found, nothing to renew")
		return nil
	}

	// Process each metadata file for renewal
	for _, metadataPath := range metadataFiles {
		if err := h.processMetadataFile(ctx, cfg, metadataPath); err != nil {
			log.Error("Error processing metadata file", "path", metadataPath, "error", err)
			// Continue with other files even if one fails
		}
	}

	return nil
}

// processMetadataFile processes a single metadata file
func (h *KerberosArnLeaseHandler) processMetadataFile(ctx context.Context, cfg aws.Config, metadataPath string) error {
	log := logger.GetInstance()

	ticketInfoList, err := metadata_utils.ReadMetadataJSON(metadataPath)
	if err != nil {
		log.Error("Failed to read metadata file", "path", metadataPath, "error", err)
		return err
	}

	if len(ticketInfoList) == 0 {
		log.Warn("No ticket information found in metadata file", "path", metadataPath)
		return nil
	}

	// Process each ticket in the metadata file
	for _, ticketInfo := range ticketInfoList {
		if err := h.processTicket(ctx, cfg, ticketInfo); err != nil {
			log.Warn("Error processing ticket", "path", ticketInfo.KrbFilePath, "error", err)
			// Continue with other tickets even if one fails
		}
	}

	return nil
}

// processTicket processes a single ticket for renewal
func (h *KerberosArnLeaseHandler) processTicket(ctx context.Context, cfg aws.Config, ticketInfo *types.TicketInfo) error {
	log := logger.GetInstance()

	// Skip if no credential spec info is available
	if ticketInfo.CredspecInfo == "" {
		log.Info("No credential spec info available for ticket", "path", ticketInfo.KrbFilePath)
		return nil
	}

	// Get credential spec and parse it
	krbTicketArn, err := h.getAndParseCredSpec(ctx, cfg, ticketInfo)
	if err != nil {
		return err
	}

	// Get and validate credentials
	username, password, domain, distinguishedName, err := h.getAndValidateCredentials(ctx, cfg, krbTicketArn)
	if err != nil {
		return err
	}

	// Update ticket info with retrieved credentials
	ticketInfo.DomainlessUser = username
	ticketInfo.DomainName = domain
	ticketInfo.DistinguishedName = distinguishedName

	// Renew the Kerberos tickets
	if err := h.renewKerberosTickets(ticketInfo, username, password, domain); err != nil {
		return err
	}

	log.Info("Successfully renewed Kerberos ticket for",
		"user", username,
		"service_account", ticketInfo.ServiceAccountName,
		"krb_file_path", ticketInfo.KrbFilePath)

	grpc_utils.SecureClearString(&username)
	grpc_utils.SecureClearString(&password)

	return nil
}

// getAndParseCredSpec retrieves and parses the credential spec from S3
func (h *KerberosArnLeaseHandler) getAndParseCredSpec(ctx context.Context, cfg aws.Config, ticketInfo *types.TicketInfo) (*types.KerberosTicketArnMapping, error) {
	log := logger.GetInstance()

	// Retrieve credential spec from S3
	credSpecContent, err := aws_utils.RetrieveCredSpecFromS3(ctx, cfg, ticketInfo.CredspecInfo)
	if err != nil || credSpecContent == "" {
		log.Error("Credential spec cannot be retrieved from S3", "error", err)
		return nil, fmt.Errorf("credential spec cannot be retrieved from S3: %w", err)
	}

	// Parse the credential spec
	krbTicketArn := &types.KerberosTicketArnMapping{}
	if err := grpc_utils.ParseCredSpecDomainless(credSpecContent, ticketInfo, krbTicketArn); err != nil {
		log.Error("Invalid credential spec fields", "error", err)
		return nil, fmt.Errorf("invalid credential spec fields: %w", err)
	}

	return krbTicketArn, nil
}

// getAndValidateCredentials retrieves and validates credentials from Secrets Manager
func (h *KerberosArnLeaseHandler) getAndValidateCredentials(ctx context.Context, cfg aws.Config, krbTicketArn *types.KerberosTicketArnMapping) (string, string, string, string, error) {
	log := logger.GetInstance()

	// Get secrets ARN
	secretsArn := krbTicketArn.CredentialDomainlessUserArn
	if secretsArn == "" {
		log.Error("Invalid Secrets Manager ARN")
		return "", "", "", "", fmt.Errorf("invalid secrets manager ARN")
	}

	// Retrieve credentials from Secrets Manager
	secretMap, err := aws_utils.GetSecretFromSecretsManagerWithConfig(ctx, cfg, secretsArn)
	if err != nil {
		log.Error("Failed to retrieve credentials from secrets manager", "error", err)
		return "", "", "", "", fmt.Errorf("failed to retrieve credentials from secrets manager: %w", err)
	}

	// Extract credentials from the secret
	username, password, domain, distinguishedName, err := aws_utils.ExtractCredentialsFromSecret(secretMap)
	if err != nil {
		log.Error("Failed to extract credentials from secret", "error", err)
		return "", "", "", "", fmt.Errorf("failed to extract credentials from secret: %w", err)
	}

	// Validate domain and username
	if !aws_utils.IsValidDomain(domain) || aws_utils.ContainsInvalidCharactersInADAccountName(username) {
		log.Error("Invalid domainName/username")
		return "", "", "", "", fmt.Errorf("invalid domainName/username")
	}

	// Validate credential lengths
	if !h.validateCredentials(username, password, domain) {
		return "", "", "", "", fmt.Errorf("invalid credentials")
	}

	return username, password, domain, distinguishedName, nil
}

// renewKerberosTickets creates/renews Kerberos tickets for the user and gMSA account
func (h *KerberosArnLeaseHandler) renewKerberosTickets(ticketInfo *types.TicketInfo, username, password, domain string) error {
	log := logger.GetInstance()

	const numRetries = 1
	for i := 0; i <= numRetries; i++ {
		// Generate Kerberos ticket using username and password (user TGT)
		if err := h.krbClient.CreateTicketUsingUsernamePassword(
			domain,
			username,
			password,
		); err != nil {
			log.Error("Failed to generate Kerberos ticket for domainless user", "error", err, "attempt", i+1)
			return fmt.Errorf("failed to generate Kerberos ticket for domainless user: %w", err)
		}

		// Create ticket for gMSA account (LDAP search + ticket creation)
		if err := h.krbClient.CreateTicketForGMSA(ticketInfo); err != nil {
			log.Error("Failed to create gMSA ticket, will regenerate user TGT and retry",
				"error", err, "attempt", i+1, "max_attempts", numRetries+1)
			continue
		}

		return nil
	}

	return fmt.Errorf("failed to create gMSA ticket after %d attempts", numRetries+1)
}
