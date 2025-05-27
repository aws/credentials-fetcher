package metadata_utils

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// GetMetadataFilePaths returns paths to all metadata files in the given directory
func GetMetadataFilePaths(krbDir string) ([]string, error) {
	var metadataFiles []string

	err := filepath.Walk(krbDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.Contains(info.Name(), "_metadata") {
			metadataFiles = append(metadataFiles, path)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory: %w", err)
	}

	return metadataFiles, nil
}

// ReadMetadataJSON reads and parses a metadata JSON file
func ReadMetadataJSON(filePath string) ([]*types.TicketInfo, error) {
	data, err := os.ReadFile(filePath) // #nosec G304
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	// First try the new format with krb_ticket_info wrapper
	var metadataRoot struct {
		KrbTicketInfo []map[string]interface{} `json:"krb_ticket_info"`
	}

	if err := json.Unmarshal(data, &metadataRoot); err == nil && len(metadataRoot.KrbTicketInfo) > 0 {
		tickets := make([]*types.TicketInfo, len(metadataRoot.KrbTicketInfo))
		for i, ticket := range metadataRoot.KrbTicketInfo {
			tickets[i] = &types.TicketInfo{}

			if val, ok := ticket["krb_file_path"].(string); ok {
				tickets[i].KrbFilePath = val
			}
			if val, ok := ticket["service_account_name"].(string); ok {
				tickets[i].ServiceAccountName = val
			}
			if val, ok := ticket["domain_name"].(string); ok {
				tickets[i].DomainName = val
			}
			if val, ok := ticket["domainless_user"].(string); ok {
				tickets[i].DomainlessUser = val
			}
			if val, ok := ticket["distinguished_name"].(string); ok {
				tickets[i].DistinguishedName = val
			}
			if val, ok := ticket["credspec_info"].(string); ok {
				tickets[i].CredspecInfo = val
			}
			if val, ok := ticket["credential_arn"].(string); ok {
				tickets[i].CredentialArn = val
			}
		}
		return tickets, nil
	}

	// If that fails, try the old format (direct array of ticket info)
	var tickets []*types.TicketInfo
	if err := json.Unmarshal(data, &tickets); err != nil {
		return nil, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	return tickets, nil
}

// WriteMetaDataJSON writes metadata about Kerberos tickets to a JSON file
func WriteMetaDataJSON(ticketInfoList []*types.TicketInfo, leaseID string, krbFilesDir string) error {
	// Create the metadata file path
	metaFileName := leaseID + "_metadata.json"
	filePath := filepath.Join(krbFilesDir, leaseID, metaFileName)

	// Create the directory structure
	dirPath := filepath.Dir(filePath)
	// #nosec G301
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create metadata directory: %v", err)
	}

	// Create the JSON structure
	root := make(map[string]interface{})
	krbTicketInfoParent := make([]map[string]interface{}, 0)

	for _, ticketInfo := range ticketInfoList {
		ticket := map[string]interface{}{
			"krb_file_path":        ticketInfo.KrbFilePath,
			"service_account_name": ticketInfo.ServiceAccountName,
			"domain_name":          ticketInfo.DomainName,
			"domainless_user":      ticketInfo.DomainlessUser,
			"distinguished_name":   ticketInfo.DistinguishedName,
			"credspec_info":        ticketInfo.CredspecInfo,
		}

		// Only include credential_arn if it's not empty
		if ticketInfo.CredentialArn != "" {
			ticket["credential_arn"] = ticketInfo.CredentialArn
		}

		krbTicketInfoParent = append(krbTicketInfoParent, ticket)
	}

	root["krb_ticket_info"] = krbTicketInfoParent

	// Marshal the JSON
	jsonData, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal metadata to JSON: %v", err)
	}

	// Write the JSON to file
	// #nosec G306
	if err := os.WriteFile(filePath, jsonData, 0644); err != nil {
		return fmt.Errorf("failed to write JSON file: %v", err)
	}

	return nil
}
