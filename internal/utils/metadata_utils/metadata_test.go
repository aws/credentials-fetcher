package metadata_utils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGetMetadataFilePaths(t *testing.T) {
	// Create temporary test directory
	tempDir, err := os.MkdirTemp("", "kerberos_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test files
	validFiles := []string{
		"valid_metadata_1.json",
		"another_metadata_2.json",
		"service_metadata_3.json",
	}

	invalidFiles := []string{
		"notmetadata.json",
		"metadata.txt",
		"test.json",
	}

	// Create valid metadata files
	for _, file := range validFiles {
		path := filepath.Join(tempDir, file)
		err := os.WriteFile(path, []byte("{}"), 0644)
		require.NoError(t, err)
	}

	// Create non-metadata files
	for _, file := range invalidFiles {
		path := filepath.Join(tempDir, file)
		err := os.WriteFile(path, []byte("{}"), 0644)
		require.NoError(t, err)
	}

	// Test getting metadata files
	files, err := GetMetadataFilePaths(tempDir)
	require.NoError(t, err)

	// Verify only metadata files are returned
	assert.Equal(t, len(validFiles), len(files))
	for _, file := range files {
		assert.Contains(t, file, "_metadata")
	}

	// Test with non-existent directory
	_, err = GetMetadataFilePaths("/nonexistent/directory")
	assert.Error(t, err)

	// Test with directory without metadata files
	emptyDir, err := os.MkdirTemp("", "empty_*")
	require.NoError(t, err)
	defer os.RemoveAll(emptyDir)

	files, err = GetMetadataFilePaths(emptyDir)
	require.NoError(t, err)
	assert.Empty(t, files)
}

func TestReadMetadataJSON(t *testing.T) {
	// Create temporary test file
	tempFile, err := os.CreateTemp("", "metadata_test_*.json")
	require.NoError(t, err)
	defer os.Remove(tempFile.Name())

	// Test valid JSON
	validJSON := `[
		{
			"krb_file_path": "/tmp/ticket1",
			"service_account_name": "service1@DOMAIN",
			"domain_name": "DOMAIN",
			"domainless_user": "service1",
			"distinguished_name": "CN=service1,DC=domain",
			"credspec_info": "info1"
		},
		{
			"krb_file_path": "/tmp/ticket2",
			"service_account_name": "service2@DOMAIN",
			"domain_name": "DOMAIN",
			"domainless_user": "service2",
			"distinguished_name": "CN=service2,DC=domain",
			"credspec_info": "info2"
		}
	]`

	err = os.WriteFile(tempFile.Name(), []byte(validJSON), 0644)
	require.NoError(t, err)

	tickets, err := ReadMetadataJSON(tempFile.Name())
	require.NoError(t, err)
	assert.Len(t, tickets, 2)
	assert.Equal(t, "/tmp/ticket1", tickets[0].KrbFilePath)
	assert.Equal(t, "service1@DOMAIN", tickets[0].ServiceAccountName)
	assert.Equal(t, "DOMAIN", tickets[0].DomainName)
	assert.Equal(t, "service1", tickets[0].DomainlessUser)
	assert.Equal(t, "CN=service1,DC=domain", tickets[0].DistinguishedName)
	assert.Equal(t, "info1", tickets[0].CredspecInfo)

	assert.Equal(t, "/tmp/ticket2", tickets[1].KrbFilePath)
	assert.Equal(t, "service2@DOMAIN", tickets[1].ServiceAccountName)
	assert.Equal(t, "DOMAIN", tickets[1].DomainName)
	assert.Equal(t, "service2", tickets[1].DomainlessUser)
	assert.Equal(t, "CN=service2,DC=domain", tickets[1].DistinguishedName)
	assert.Equal(t, "info2", tickets[1].CredspecInfo)

	// Test invalid JSON
	err = os.WriteFile(tempFile.Name(), []byte("invalid json"), 0644)
	require.NoError(t, err)

	_, err = ReadMetadataJSON(tempFile.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse metadata JSON")

	// Test empty JSON array
	err = os.WriteFile(tempFile.Name(), []byte("[]"), 0644)
	require.NoError(t, err)

	tickets, err = ReadMetadataJSON(tempFile.Name())
	require.NoError(t, err)
	assert.Empty(t, tickets)

	// Test non-existent file
	_, err = ReadMetadataJSON("/nonexistent/file.json")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to read metadata file")

	// Test malformed JSON
	err = os.WriteFile(tempFile.Name(), []byte(`[{"krb_file_path": "/tmp/ticket1",`), 0644)
	require.NoError(t, err)

	_, err = ReadMetadataJSON(tempFile.Name())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to parse metadata JSON")

	// Test JSON with missing required fields
	incompleteJSON := `[
		{
			"krb_file_path": "/tmp/ticket1"
		}
	]`

	err = os.WriteFile(tempFile.Name(), []byte(incompleteJSON), 0644)
	require.NoError(t, err)

	tickets, err = ReadMetadataJSON(tempFile.Name())
	require.NoError(t, err)
	assert.Len(t, tickets, 1)
	assert.Equal(t, "/tmp/ticket1", tickets[0].KrbFilePath)
	assert.Empty(t, tickets[0].ServiceAccountName)
	assert.Empty(t, tickets[0].DomainName)
}
