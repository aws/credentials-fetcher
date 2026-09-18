package api

import (
	"context"
	"fmt"
	"os"
	"strings"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/aws_utils"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/metadata_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"

	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
)

// RenewNonDomainJoinedKerberosLeaseInterface extends KerberosTicketOperations with Renew-specific operations
type RenewNonDomainJoinedKerberosLeaseInterface interface {
	KerberosTicketOperations

	// RenewNonDomainJoinedKerberosLease implements the RenewNonDomainJoinedKerberosLease RPC method
	RenewNonDomainJoinedKerberosLease(ctx context.Context, req *pb.RenewNonDomainJoinedKerberosLeaseRequest) (*pb.RenewNonDomainJoinedKerberosLeaseResponse, error)
}

// RenewNonDomainJoinedKerberosLease implements the RenewNonDomainJoinedKerberosLease RPC method
func (h *NonDomainJoinedKerberosHandler) RenewNonDomainJoinedKerberosLease(ctx context.Context, req *pb.RenewNonDomainJoinedKerberosLeaseRequest) (response *pb.RenewNonDomainJoinedKerberosLeaseResponse, responseErr error) {
	log.Info("Received RenewNonDomainJoinedKerberosLease request")
	snapshots := make(map[string]fileSnapshot)
	defer func() {
		if responseErr != nil {
			if rollbackErr := restoreFileSnapshots(snapshots); rollbackErr != nil {
				responseErr = fmt.Errorf("%w; rollback failed: %v", responseErr, rollbackErr)
			}
		}
		clearFileSnapshots(snapshots)
	}()

	// Defer credential clearing to ensure it happens even on early returns
	defer func() {
		grpc_utils.SecureClearString(&req.Username)
		grpc_utils.SecureClearString(&req.Password)
	}()

	// Parse blue/green username rotation format ("oldUser:newUser").
	// When usernames are rotated in AWS Secrets Manager, the caller supplies
	// the old and new usernames separated by ':' so we can match existing
	// tickets (by the old name) and recreate them with the new credentials.
	matchUsername, activeUsername, isRotation := grpc_utils.ParseBlueGreenUsername(req.Username)
	if isRotation {
		if matchUsername == "" || activeUsername == "" {
			return nil, fmt.Errorf("blue/green rotation format requires both old and new usernames (\"oldUser:newUser\")")
		}
		if matchUsername == activeUsername {
			// Same username on both sides — treat as a normal renewal.
			isRotation = false
		} else {
			log.Info("Detected username with colon separator",
				"match_username", matchUsername, "active_username", activeUsername)
		}
	}

	// Validate each username part individually (the raw "old:new" string
	// would fail ValidateAccountName because ':' is invalid in AD usernames)
	if err := h.ValidateCredentials(activeUsername, req.Password, req.Domain); err != nil {
		return nil, err
	}
	if isRotation {
		if err := grpc_utils.ValidateAccountName(matchUsername); err != nil {
			return nil, fmt.Errorf("invalid old username: %v", err)
		}
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

	// Pending metadata updates for rotation — written only after successful
	// ticket recreation to avoid inconsistent state on failure.
	type pendingMetadataUpdate struct {
		path           string
		ticketInfoList []*types.TicketInfo
	}
	var pendingUpdates []pendingMetadataUpdate

	// Process each metadata file
	for _, metadataPath := range metadataFiles {
		// Read ticket info from metadata file
		ticketInfoList, err := metadata_utils.ReadMetadataJSON(metadataPath)
		if err != nil {
			log.Warn("Failed to read metadata file", "path", metadataPath, "error", err)
			continue // Skip this file and try the next one
		}
		if err := captureFileSnapshot(snapshots, metadataPath); err != nil {
			return nil, fmt.Errorf("failed to snapshot metadata file %s: %v", metadataPath, err)
		}

		// Filter ticket infos that match the provided (or old/blue) username
		var matchingTicketInfos []*types.TicketInfo
		for _, ticketInfo := range ticketInfoList {
			if ticketInfo.DomainlessUser == matchUsername {
				matchingTicketInfos = append(matchingTicketInfos, ticketInfo)
				continue
			}

			// If rotation is active and the ticket already has the new (green) username,
			// the rotation was already completed — treat as a normal renewal match.
			if isRotation && ticketInfo.DomainlessUser == activeUsername {
				matchingTicketInfos = append(matchingTicketInfos, ticketInfo)
				continue
			}

			// If DomainlessUser is empty and CredentialArn is available, extract username from the secret
			if ticketInfo.DomainlessUser == "" && ticketInfo.CredentialArn != "" {
				secretMap, err := aws_utils.GetSecretFromSecretsManagerWithContext(ctx, ticketInfo.CredentialArn)
				if err != nil {
					log.Warn("Failed to retrieve secret from CredentialArn", "arn", ticketInfo.CredentialArn, "error", err)
					continue
				}

				username, _, _, _, err := aws_utils.ExtractCredentialsFromSecret(secretMap)
				if err != nil {
					log.Warn("Failed to extract username from secret", "arn", ticketInfo.CredentialArn, "error", err)
					continue
				}

				legacyUsername, matched := matchLegacyUsername(username, matchUsername, activeUsername, isRotation)
				if matched {
					ticketInfo.DomainlessUser = legacyUsername
					matchingTicketInfos = append(matchingTicketInfos, ticketInfo)
					log.Info("Matched ticket via CredentialArn username", "username", username, "arn", ticketInfo.CredentialArn)
				}
			}
		}

		if len(matchingTicketInfos) == 0 {
			log.Info("No matching tickets found for user",
				"match_username", matchUsername, "metadata_path", metadataPath)
			continue // Skip to next metadata file
		}

		// Determine if this is an actual rotation or if rotation was already completed.
		// If all matched tickets already have the active username, treat as normal renewal.
		needsRotation := false
		if isRotation {
			for _, ticketInfo := range matchingTicketInfos {
				if ticketInfo.DomainlessUser == matchUsername {
					needsRotation = true
					break
				}
			}
		}

		// When rotating usernames, only tickets that still have the old username
		// need recreation. Tickets already carrying the active username are renewed
		// normally — this handles the mixed-state case where some tickets in a
		// metadata file were already rotated.
		if needsRotation {
			log.Info("Blue/green username rotation detected",
				"match_username", matchUsername, "active_username", activeUsername)
			for _, ticketInfo := range matchingTicketInfos {
				if err := h.captureRenewalCacheSnapshot(snapshots, ticketInfo.KrbFilePath); err != nil {
					return nil, err
				}
				if ticketInfo.DomainlessUser == matchUsername {
					// Update DomainlessUser to the new (green) username so that
					// subsequent renewals and metadata lookups use the new name.
					ticketInfo.DomainlessUser = activeUsername
					ticketsToRecreate = append(ticketsToRecreate, ticketInfo)
				} else {
					// Already rotated — renew normally
					err = h.krbClient.RenewKerberosTicket(ctx, ticketInfo.KrbFilePath)
					if err == nil {
						renewedKrbFilePaths = append(renewedKrbFilePaths, ticketInfo.KrbFilePath)
						log.Info("Successfully renewed already-rotated ticket directly", "path", ticketInfo.KrbFilePath)
					} else {
						log.Warn("Direct renewal failed for already-rotated ticket, will recreate",
							"error", err, "path", ticketInfo.KrbFilePath)
						ticketsToRecreate = append(ticketsToRecreate, ticketInfo)
					}
				}
			}
			// Queue metadata write — deferred until after successful ticket recreation
			// to avoid inconsistent state if CreateKerberosTickets fails.
			pendingUpdates = append(pendingUpdates, pendingMetadataUpdate{metadataPath, ticketInfoList})
			log.Info("Username rotation: tickets queued for recreation",
				"recreate_count", len(ticketsToRecreate), "already_renewed", len(renewedKrbFilePaths))
		} else {
			// Normal (non-rotation) path: try direct renewal first
			for _, ticketInfo := range matchingTicketInfos {
				if err := h.captureRenewalCacheSnapshot(snapshots, ticketInfo.KrbFilePath); err != nil {
					return nil, err
				}
				err = h.krbClient.RenewKerberosTicket(ctx, ticketInfo.KrbFilePath)
				if err == nil {
					renewedKrbFilePaths = append(renewedKrbFilePaths, ticketInfo.KrbFilePath)
					log.Info("Successfully renewed Kerberos ticket directly", "path", ticketInfo.KrbFilePath)
				} else {
					log.Warn("Direct renewal failed, will recreate the ticket",
						"error", err, "path", ticketInfo.KrbFilePath)
					ticketsToRecreate = append(ticketsToRecreate, ticketInfo)
				}
			}
		}
	}

	if len(ticketsToRecreate) > 0 {
		log.Info("Attempting to recreate tickets that couldn't be renewed directly", "count", len(ticketsToRecreate))

		// Use the active (green) username for ticket creation
		recreatedPaths, err := h.RecreateKerberosTickets(ctx, req.Domain, activeUsername, req.Password, ticketsToRecreate)
		if err != nil {
			log.Error("Failed to recreate Kerberos tickets", "error", err)
			return nil, fmt.Errorf("failed to recreate Kerberos tickets: %v", err)
		}
		renewedKrbFilePaths = append(renewedKrbFilePaths, recreatedPaths...)
		log.Info("Successfully recreated Kerberos tickets", "count", len(recreatedPaths))

		// Persist rotation metadata only after tickets were successfully recreated.
		// This ensures on-disk metadata stays consistent with actual ticket state.
		// Attempt all writes and collect errors so the caller gets an accurate
		// picture (some metadata files may have been updated successfully).
		var metadataErrors []string
		for _, pu := range pendingUpdates {
			if err := metadata_utils.UpdateMetadataJSON(pu.path, pu.ticketInfoList); err != nil {
				metadataErrors = append(metadataErrors, fmt.Sprintf("%s: %v", pu.path, err))
				log.Error("Failed to persist username rotation to metadata", "path", pu.path, "error", err)
			}
		}
		if len(metadataErrors) > 0 {
			return nil, fmt.Errorf("metadata persistence failed for %d file(s): %s",
				len(metadataErrors), strings.Join(metadataErrors, "; "))
		}
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

type fileSnapshot struct {
	data    []byte
	mode    os.FileMode
	existed bool
}

func captureFileSnapshot(snapshots map[string]fileSnapshot, path string) error {
	if _, ok := snapshots[path]; ok {
		return nil
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			snapshots[path] = fileSnapshot{}
			return nil
		}
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to snapshot symlink: %s", path)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- validated lease paths are restored on failed renewal
	if err != nil {
		return err
	}
	snapshots[path] = fileSnapshot{data: data, mode: info.Mode().Perm(), existed: true}
	return nil
}

func restoreFileSnapshots(snapshots map[string]fileSnapshot) error {
	var restorationErrors []string
	for path, snapshot := range snapshots {
		if !snapshot.existed {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				log.Error("Failed to remove file created during failed renewal", "path", path, "error", err)
				restorationErrors = append(restorationErrors, fmt.Sprintf("remove %s: %v", path, err))
			}
			continue
		}
		if err := os.WriteFile(path, snapshot.data, snapshot.mode); err != nil { // #nosec G304 -- path was captured from validated metadata
			log.Error("Failed to restore file after renewal error", "path", path, "error", err)
			restorationErrors = append(restorationErrors, fmt.Sprintf("restore %s: %v", path, err))
		}
	}
	if len(restorationErrors) > 0 {
		return fmt.Errorf("failed to restore %d file(s): %s", len(restorationErrors), strings.Join(restorationErrors, "; "))
	}
	return nil
}

func clearFileSnapshots(snapshots map[string]fileSnapshot) {
	for path, snapshot := range snapshots {
		grpc_utils.SecureClearBytes(snapshot.data)
		delete(snapshots, path)
	}
}

func (h *NonDomainJoinedKerberosHandler) captureRenewalCacheSnapshot(snapshots map[string]fileSnapshot, path string) error {
	if err := h.validateRenewalCachePath(path); err != nil {
		return err
	}
	if err := captureFileSnapshot(snapshots, path); err != nil {
		return fmt.Errorf("failed to snapshot Kerberos cache %s: %v", path, err)
	}
	return nil
}

func matchLegacyUsername(secretUsername, matchUsername, activeUsername string, isRotation bool) (string, bool) {
	secretMatch, secretActive, secretIsRotation := grpc_utils.ParseBlueGreenUsername(secretUsername)
	if secretIsRotation {
		if isRotation && secretMatch == matchUsername && secretActive == activeUsername {
			return matchUsername, true
		}
		return "", false
	}
	if secretUsername == matchUsername {
		return matchUsername, true
	}
	if isRotation && secretUsername == activeUsername {
		return activeUsername, true
	}
	return "", false
}
