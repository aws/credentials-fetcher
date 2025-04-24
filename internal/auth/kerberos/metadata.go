package kerberos

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
func ReadMetadataJSON(filePath string) ([]*TicketInfo, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	var tickets []*TicketInfo
	if err := json.Unmarshal(data, &tickets); err != nil {
		return nil, fmt.Errorf("failed to parse metadata JSON: %w", err)
	}

	return tickets, nil
}
