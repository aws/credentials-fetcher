package api

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/auth/kerberos"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/metadata_utils"
)

// KerberosLeaseHandler handles Kerberos lease operations
type KerberosLeaseHandler struct {
	krbFilesDir string
	krbClient   *kerberos.Client
}

// NewKerberosLeaseHandler creates a new handler for Kerberos lease operations
func NewKerberosLeaseHandler(krbFilesDir string, krbClient *kerberos.Client) *KerberosLeaseHandler {
	return &KerberosLeaseHandler{
		krbFilesDir: krbFilesDir,
		krbClient:   krbClient,
	}
}

// DeleteKerberosLease implements the DeleteKerberosLease RPC method
func (h *KerberosLeaseHandler) DeleteKerberosLease(ctx context.Context, req *pb.DeleteKerberosLeaseRequest) (*pb.DeleteKerberosLeaseResponse, error) {
	log.Info("Received DeleteKerberosLease request", "lease_id", req.LeaseId)

	// Validate request
	if err := h.validateRequest(req); err != nil {
		return nil, err
	}

	// Get the lease directory path
	leaseDir := filepath.Join(h.krbFilesDir, req.LeaseId)
	log.Info("Cleaning up ", "path", leaseDir)

	// Check if the lease directory exists
	if _, err := os.Stat(leaseDir); os.IsNotExist(err) {
		log.Error("Lease directory does not exist", "lease_id", req.LeaseId, "path", leaseDir)
		return nil, fmt.Errorf("lease with ID %s does not exist", req.LeaseId)
	}

	// Get metadata for the lease to know which files to delete
	metadataPath := filepath.Join(leaseDir, req.LeaseId+"_metadata.json")
	ticketInfoList, err := metadata_utils.ReadMetadataJSON(metadataPath)
	if err != nil {
		log.Error("Failed to read metadata for lease", "lease_id", req.LeaseId, "error", err)
		return nil, fmt.Errorf("failed to read metadata for lease %s: %v", req.LeaseId, err)
	}

	// Delete all Kerberos files associated with the lease using the kerberos client
	var deletedKrbFilePaths []string
	for _, ticketInfo := range ticketInfoList {
		krbFilePath := ticketInfo.KrbFilePath
		log.Info("Deleting Kerberos file using kerberos client", "path", krbFilePath)

		// Use the kerberos client to properly delete the ticket
		if err := h.krbClient.DeleteKerberosLease(ctx, krbFilePath); err != nil {
			log.Error("Failed to delete Kerberos file using kerberos client",
				"path", krbFilePath,
				"error", err)
			// Continue with deletion of other files even if one fails
		} else {
			deletedKrbFilePaths = append(deletedKrbFilePaths, krbFilePath)
		}

		// Delete the directory containing the Kerberos file if it's empty
		dirPath := filepath.Dir(krbFilePath)
		if isEmpty, _ := isDirEmpty(dirPath); isEmpty {
			if err := os.RemoveAll(dirPath); err != nil {
				log.Error("Failed to delete directory", "path", dirPath, "error", err)
				// Continue with deletion of other directories even if one fails
			}
		}
	}

	// Delete the metadata file if it still exists
	if _, err := os.Stat(metadataPath); err == nil {
		if err := os.Remove(metadataPath); err != nil {
			log.Error("Failed to delete metadata file", "path", metadataPath, "error", err)
		}
	}

	// Delete the lease directory if it's empty
	if isEmpty, _ := isDirEmpty(leaseDir); isEmpty {
		if err := os.RemoveAll(leaseDir); err != nil {
			log.Error("Failed to delete lease directory", "path", leaseDir, "error", err)
			return nil, fmt.Errorf("failed to delete lease directory: %v", err)
		}
	}

	log.Info("Successfully deleted Kerberos lease", "lease_id", req.LeaseId, "deleted_files", deletedKrbFilePaths)

	// Return the response with lease ID and deleted Kerberos file paths
	return &pb.DeleteKerberosLeaseResponse{
		LeaseId:                  req.LeaseId,
		DeletedKerberosFilePaths: deletedKrbFilePaths,
	}, nil
}

// validateRequest validates the request parameters
func (h *KerberosLeaseHandler) validateRequest(req *pb.DeleteKerberosLeaseRequest) error {
	// Validate lease ID
	if req.LeaseId == "" {
		log.Error("Missing lease ID in request")
		return fmt.Errorf("lease ID is required")
	}

	// Validate lease ID length against Linux filename limit
	if len(req.LeaseId) > constants.MaxFilenameLength {
		log.Error("Lease ID exceeds maximum filename length", "lease_id_length", len(req.LeaseId), "max_length", constants.MaxFilenameLength)
		return fmt.Errorf("lease ID length %d exceeds maximum filename length %d", len(req.LeaseId), constants.MaxFilenameLength)
	}

	return nil
}

// isDirEmpty checks if a directory is empty
func isDirEmpty(dirPath string) (bool, error) {
	// Validate the path to prevent path traversal attacks
	cleanPath := filepath.Clean(dirPath)
	if !filepath.IsAbs(cleanPath) {
		return false, fmt.Errorf("path must be absolute: %s", dirPath)
	}

	// Use filepath.Clean to normalize the path and remove any ".." elements
	f, err := os.Open(cleanPath) // #nosec G304 -- path is validated above
	if err != nil {
		return false, err
	}
	defer func(f *os.File) {
		err := f.Close()
		if err != nil {
			fmt.Printf("%s", err.Error())
			return
		}
	}(f)

	// Read just one entry
	_, err = f.Readdirnames(1)
	if err != nil {
		if err.Error() == "EOF" {
			// Directory is empty
			return true, nil
		}
		return false, err
	}

	// Directory is not empty
	return false, nil
}
