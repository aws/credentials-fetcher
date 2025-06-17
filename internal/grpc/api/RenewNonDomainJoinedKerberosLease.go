package api

import (
	"context"
	"fmt"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"

	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/metadata_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// RenewNonDomainJoinedKerberosLeaseInterface extends KerberosTicketOperations with Renew-specific operations
type RenewNonDomainJoinedKerberosLeaseInterface interface {
	KerberosTicketOperations

	// RenewNonDomainJoinedKerberosLease implements the RenewNonDomainJoinedKerberosLease RPC method
	RenewNonDomainJoinedKerberosLease(ctx context.Context, req *pb.RenewNonDomainJoinedKerberosLeaseRequest) (*pb.RenewNonDomainJoinedKerberosLeaseResponse, error)
}

// RenewNonDomainJoinedKerberosLease implements the RenewNonDomainJoinedKerberosLease RPC method
func (h *NonDomainJoinedKerberosHandler) RenewNonDomainJoinedKerberosLease(ctx context.Context, req *pb.RenewNonDomainJoinedKerberosLeaseRequest) (*pb.RenewNonDomainJoinedKerberosLeaseResponse, error) {
	log.Info("Received RenewNonDomainJoinedKerberosLease request")

	// Defer credential clearing to ensure it happens even on early returns
	defer func() {
		grpc_utils.SecureClearString(&req.Username)
		grpc_utils.SecureClearString(&req.Password)
	}()

	// Validate request
	if err := h.ValidateCredentials(req.Username, req.Password, req.Domain); err != nil {
		return nil, err
	}

	// Get all metadata files from the Kerberos files directory
	metadataFiles, err := metadata_utils.GetMetadataFilePaths(h.krbFilesDir)
	if err != nil {
		log.Error("Failed to get metadata files", "error", err)
		return nil, fmt.Errorf("failed to get metadata files: %v", err)
	}

	if len(metadataFiles) == 0 {
		log.Error("No metadata files found in directory", "directory", h.krbFilesDir)
		return nil, fmt.Errorf("no metadata files found in directory: %s", h.krbFilesDir)
	}

	var renewedKrbFilePaths []string
	var ticketsToRecreate []*types.TicketInfo

	// Process each metadata file
	for _, metadataPath := range metadataFiles {
		// Read ticket info from metadata file
		ticketInfoList, err := metadata_utils.ReadMetadataJSON(metadataPath)
		if err != nil {
			log.Warn("Failed to read metadata file", "path", metadataPath, "error", err)
			continue // Skip this file and try the next one
		}

		// Filter ticket infos that match the provided username
		var matchingTicketInfos []*types.TicketInfo
		for _, ticketInfo := range ticketInfoList {
			if ticketInfo.DomainlessUser == req.Username {
				matchingTicketInfos = append(matchingTicketInfos, ticketInfo)
			}
		}

		if len(matchingTicketInfos) == 0 {
			log.Info("No matching tickets found for user", "username", req.Username, "metadata_path", metadataPath)
			continue // Skip to next metadata file
		}

		// First try to renew each matching ticket directly using krbClient.RenewKerberosTicket
		for _, ticketInfo := range matchingTicketInfos {
			err = h.krbClient.RenewKerberosTicket(ctx, ticketInfo.KrbFilePath)
			if err == nil {
				// Successfully renewed the ticket
				renewedKrbFilePaths = append(renewedKrbFilePaths, ticketInfo.KrbFilePath)
				log.Info("Successfully renewed Kerberos ticket directly", "path", ticketInfo.KrbFilePath)
			} else {
				log.Warn("Direct renewal failed, will recreate the ticket", "error", err, "path", ticketInfo.KrbFilePath)
				// Add to list of tickets that need recreation
				ticketsToRecreate = append(ticketsToRecreate, ticketInfo)
			}
		}
	}

	// If we have tickets that need recreation, use CreateKerberosTickets to recreate them
	if len(ticketsToRecreate) > 0 {
		log.Info("Attempting to recreate tickets that couldn't be renewed directly", "count", len(ticketsToRecreate))

		// Use CreateKerberosTickets to recreate the tickets
		recreatedPaths, err := h.CreateKerberosTickets(ctx, req.Domain, req.Username, req.Password, ticketsToRecreate)
		if err != nil {
			log.Error("Failed to recreate Kerberos tickets", "error", err)
			// If we have some successfully renewed tickets, return those
			if len(renewedKrbFilePaths) > 0 {
				log.Info("Returning partially renewed tickets", "count", len(renewedKrbFilePaths))
				return &pb.RenewNonDomainJoinedKerberosLeaseResponse{
					RenewedKerberosFilePaths: renewedKrbFilePaths,
				}, nil
			}
			return nil, fmt.Errorf("failed to recreate Kerberos tickets: %v", err)
		}

		// Add recreated paths to renewed paths
		renewedKrbFilePaths = append(renewedKrbFilePaths, recreatedPaths...)
		log.Info("Successfully recreated Kerberos tickets", "count", len(recreatedPaths))
	}

	if len(renewedKrbFilePaths) == 0 {
		log.Error("Failed to renew any Kerberos tickets")
		return nil, fmt.Errorf("failed to renew any Kerberos tickets")
	}

	// Return the response with renewed Kerberos file paths
	return &pb.RenewNonDomainJoinedKerberosLeaseResponse{
		RenewedKerberosFilePaths: renewedKrbFilePaths,
	}, nil
}
