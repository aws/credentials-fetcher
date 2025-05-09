package metadata_utils

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
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
	// Create temporary test directory
	tempDir, err := os.MkdirTemp("", "metadata_read_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	t.Run("New Format", func(t *testing.T) {
		// Create test metadata file with new format
		newFormatData := map[string]interface{}{
			"krb_ticket_info": []map[string]interface{}{
				{
					"krb_file_path":        "/tmp/krb5cc_test1",
					"service_account_name": "service1@EXAMPLE.COM",
					"domain_name":          "EXAMPLE.COM",
					"domainless_user":      "service1",
					"distinguished_name":   "CN=service1,DC=example,DC=com",
					"credspec_info":        "{\"test\":\"data1\"}",
					"credential_arn":       "arn:aws:secretsmanager:region:account:secret:test1",
				},
				{
					"krb_file_path":        "/tmp/krb5cc_test2",
					"service_account_name": "service2@EXAMPLE.COM",
					"domain_name":          "EXAMPLE.COM",
					"domainless_user":      "service2",
					"distinguished_name":   "CN=service2,DC=example,DC=com",
					"credspec_info":        "{\"test\":\"data2\"}",
				},
			},
		}

		newFormatPath := filepath.Join(tempDir, "new_format_metadata.json")
		newFormatJSON, err := json.Marshal(newFormatData)
		require.NoError(t, err)
		err = os.WriteFile(newFormatPath, newFormatJSON, 0644)
		require.NoError(t, err)

		// Test reading new format
		tickets, err := ReadMetadataJSON(newFormatPath)
		require.NoError(t, err)
		assert.Len(t, tickets, 2)

		// Verify first ticket
		assert.Equal(t, "/tmp/krb5cc_test1", tickets[0].KrbFilePath)
		assert.Equal(t, "service1@EXAMPLE.COM", tickets[0].ServiceAccountName)
		assert.Equal(t, "EXAMPLE.COM", tickets[0].DomainName)
		assert.Equal(t, "service1", tickets[0].DomainlessUser)
		assert.Equal(t, "CN=service1,DC=example,DC=com", tickets[0].DistinguishedName)
		assert.Equal(t, "{\"test\":\"data1\"}", tickets[0].CredspecInfo)
		assert.Equal(t, "arn:aws:secretsmanager:region:account:secret:test1", tickets[0].CredentialArn)

		// Verify second ticket
		assert.Equal(t, "/tmp/krb5cc_test2", tickets[1].KrbFilePath)
		assert.Equal(t, "service2@EXAMPLE.COM", tickets[1].ServiceAccountName)
		assert.Equal(t, "EXAMPLE.COM", tickets[1].DomainName)
		assert.Equal(t, "service2", tickets[1].DomainlessUser)
		assert.Equal(t, "CN=service2,DC=example,DC=com", tickets[1].DistinguishedName)
		assert.Equal(t, "{\"test\":\"data2\"}", tickets[1].CredspecInfo)
		assert.Empty(t, tickets[1].CredentialArn)
	})

	t.Run("Old Format", func(t *testing.T) {
		// Create test metadata file with old format
		oldFormatData := []*types.TicketInfo{
			{
				KrbFilePath:        "/tmp/krb5cc_old",
				ServiceAccountName: "oldservice@EXAMPLE.COM",
				DomainName:         "EXAMPLE.COM",
				DomainlessUser:     "oldservice",
				DistinguishedName:  "CN=oldservice,DC=example,DC=com",
				CredspecInfo:       "{\"test\":\"old\"}",
			},
		}

		oldFormatPath := filepath.Join(tempDir, "old_format_metadata.json")
		oldFormatJSON, err := json.Marshal(oldFormatData)
		require.NoError(t, err)
		err = os.WriteFile(oldFormatPath, oldFormatJSON, 0644)
		require.NoError(t, err)

		// Test reading old format
		tickets, err := ReadMetadataJSON(oldFormatPath)
		require.NoError(t, err)
		assert.Len(t, tickets, 1)
		assert.Equal(t, "/tmp/krb5cc_old", tickets[0].KrbFilePath)
		assert.Equal(t, "oldservice@EXAMPLE.COM", tickets[0].ServiceAccountName)
		assert.Equal(t, "EXAMPLE.COM", tickets[0].DomainName)
		assert.Equal(t, "oldservice", tickets[0].DomainlessUser)
		assert.Equal(t, "CN=oldservice,DC=example,DC=com", tickets[0].DistinguishedName)
		assert.Equal(t, "{\"test\":\"old\"}", tickets[0].CredspecInfo)
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		// Create invalid JSON file
		invalidPath := filepath.Join(tempDir, "invalid_metadata.json")
		err = os.WriteFile(invalidPath, []byte("invalid json"), 0644)
		require.NoError(t, err)

		// Test reading invalid JSON
		_, err := ReadMetadataJSON(invalidPath)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to parse metadata JSON")
	})

	t.Run("Non-existent File", func(t *testing.T) {
		// Test reading non-existent file
		_, err := ReadMetadataJSON("/nonexistent/file.json")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to read metadata file")
	})
}

func TestWriteMetaDataJSON(t *testing.T) {
	// Create temporary test directory
	tempDir, err := os.MkdirTemp("", "metadata_write_test_*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create metadata directory with proper permissions
	metadataDir := filepath.Join(tempDir, "metadata")
	err = os.MkdirAll(metadataDir, 0755)
	require.NoError(t, err)

	t.Run("Basic Write", func(t *testing.T) {
		// Create test ticket info
		ticketInfo := &types.TicketInfo{
			KrbFilePath:        "/tmp/krb5cc_test",
			ServiceAccountName: "testservice@EXAMPLE.COM",
			DomainName:         "EXAMPLE.COM",
			DomainlessUser:     "testservice",
			DistinguishedName:  "CN=testservice,DC=example,DC=com",
			CredspecInfo:       "{\"test\":\"data\"}",
		}

		// Test writing metadata
		leaseID := "test-lease-id"
		ticketInfoList := []*types.TicketInfo{ticketInfo}
		err = WriteMetaDataJSON(ticketInfoList, leaseID, tempDir)
		require.NoError(t, err)

		// Verify metadata file was created
		metadataPath := filepath.Join(tempDir, leaseID, leaseID+"_metadata.json")
		_, err = os.Stat(metadataPath)
		assert.NoError(t, err)

		// Read and verify the content
		data, err := os.ReadFile(metadataPath)
		require.NoError(t, err)

		var metadataRoot struct {
			KrbTicketInfo []struct {
				KrbFilePath        string `json:"krb_file_path"`
				ServiceAccountName string `json:"service_account_name"`
				DomainName         string `json:"domain_name"`
				DomainlessUser     string `json:"domainless_user"`
				DistinguishedName  string `json:"distinguished_name"`
				CredspecInfo       string `json:"credspec_info"`
			} `json:"krb_ticket_info"`
		}
		err = json.Unmarshal(data, &metadataRoot)
		require.NoError(t, err)
		assert.Len(t, metadataRoot.KrbTicketInfo, 1)
		assert.Equal(t, ticketInfo.KrbFilePath, metadataRoot.KrbTicketInfo[0].KrbFilePath)
		assert.Equal(t, ticketInfo.ServiceAccountName, metadataRoot.KrbTicketInfo[0].ServiceAccountName)
		assert.Equal(t, ticketInfo.DomainName, metadataRoot.KrbTicketInfo[0].DomainName)
		assert.Equal(t, ticketInfo.DomainlessUser, metadataRoot.KrbTicketInfo[0].DomainlessUser)
		assert.Equal(t, ticketInfo.DistinguishedName, metadataRoot.KrbTicketInfo[0].DistinguishedName)
		assert.Equal(t, ticketInfo.CredspecInfo, metadataRoot.KrbTicketInfo[0].CredspecInfo)
	})

	t.Run("With Credential ARN", func(t *testing.T) {
		// Create test ticket info with credential ARN
		ticketInfo := &types.TicketInfo{
			KrbFilePath:        "/tmp/krb5cc_test_arn",
			ServiceAccountName: "arnservice@EXAMPLE.COM",
			DomainName:         "EXAMPLE.COM",
			DomainlessUser:     "arnservice",
			DistinguishedName:  "CN=arnservice,DC=example,DC=com",
			CredspecInfo:       "{\"test\":\"arn_data\"}",
			CredentialArn:      "arn:aws:secretsmanager:region:account:secret:test-secret",
		}

		// Test writing metadata
		leaseID := "arn-lease-id"
		ticketInfoList := []*types.TicketInfo{ticketInfo}
		err = WriteMetaDataJSON(ticketInfoList, leaseID, tempDir)
		require.NoError(t, err)

		// Verify metadata file was created
		metadataPath := filepath.Join(tempDir, leaseID, leaseID+"_metadata.json")
		_, err = os.Stat(metadataPath)
		assert.NoError(t, err)

		// Read and verify the content
		data, err := os.ReadFile(metadataPath)
		require.NoError(t, err)

		var metadataRoot struct {
			KrbTicketInfo []map[string]interface{} `json:"krb_ticket_info"`
		}
		err = json.Unmarshal(data, &metadataRoot)
		require.NoError(t, err)
		assert.Len(t, metadataRoot.KrbTicketInfo, 1)
		assert.Equal(t, ticketInfo.KrbFilePath, metadataRoot.KrbTicketInfo[0]["krb_file_path"])
		assert.Equal(t, ticketInfo.ServiceAccountName, metadataRoot.KrbTicketInfo[0]["service_account_name"])
		assert.Equal(t, ticketInfo.DomainName, metadataRoot.KrbTicketInfo[0]["domain_name"])
		assert.Equal(t, ticketInfo.DomainlessUser, metadataRoot.KrbTicketInfo[0]["domainless_user"])
		assert.Equal(t, ticketInfo.DistinguishedName, metadataRoot.KrbTicketInfo[0]["distinguished_name"])
		assert.Equal(t, ticketInfo.CredspecInfo, metadataRoot.KrbTicketInfo[0]["credspec_info"])
		assert.Equal(t, ticketInfo.CredentialArn, metadataRoot.KrbTicketInfo[0]["credential_arn"])
	})

	t.Run("Multiple Tickets", func(t *testing.T) {
		// Create multiple test ticket infos
		ticketInfo1 := &types.TicketInfo{
			KrbFilePath:        "/tmp/krb5cc_test1",
			ServiceAccountName: "service1@EXAMPLE.COM",
			DomainName:         "EXAMPLE.COM",
			DomainlessUser:     "service1",
			DistinguishedName:  "CN=service1,DC=example,DC=com",
			CredspecInfo:       "{\"test\":\"data1\"}",
		}

		ticketInfo2 := &types.TicketInfo{
			KrbFilePath:        "/tmp/krb5cc_test2",
			ServiceAccountName: "service2@EXAMPLE.COM",
			DomainName:         "EXAMPLE.COM",
			DomainlessUser:     "service2",
			DistinguishedName:  "CN=service2,DC=example,DC=com",
			CredspecInfo:       "{\"test\":\"data2\"}",
			CredentialArn:      "arn:aws:secretsmanager:region:account:secret:test2",
		}

		// Test writing metadata
		leaseID := "multi-lease-id"
		ticketInfoList := []*types.TicketInfo{ticketInfo1, ticketInfo2}
		err = WriteMetaDataJSON(ticketInfoList, leaseID, tempDir)
		require.NoError(t, err)

		// Verify metadata file was created
		metadataPath := filepath.Join(tempDir, leaseID, leaseID+"_metadata.json")
		_, err = os.Stat(metadataPath)
		assert.NoError(t, err)

		// Read and verify the content
		data, err := os.ReadFile(metadataPath)
		require.NoError(t, err)

		var metadataRoot struct {
			KrbTicketInfo []map[string]interface{} `json:"krb_ticket_info"`
		}
		err = json.Unmarshal(data, &metadataRoot)
		require.NoError(t, err)
		assert.Len(t, metadataRoot.KrbTicketInfo, 2)

		// First ticket should not have credential_arn
		assert.Equal(t, "/tmp/krb5cc_test1", metadataRoot.KrbTicketInfo[0]["krb_file_path"])
		assert.Equal(t, "service1@EXAMPLE.COM", metadataRoot.KrbTicketInfo[0]["service_account_name"])
		_, hasCredArn := metadataRoot.KrbTicketInfo[0]["credential_arn"]
		assert.False(t, hasCredArn, "First ticket should not have credential_arn")

		// Second ticket should have credential_arn
		assert.Equal(t, "/tmp/krb5cc_test2", metadataRoot.KrbTicketInfo[1]["krb_file_path"])
		assert.Equal(t, "service2@EXAMPLE.COM", metadataRoot.KrbTicketInfo[1]["service_account_name"])
		assert.Equal(t, "arn:aws:secretsmanager:region:account:secret:test2", metadataRoot.KrbTicketInfo[1]["credential_arn"])
	})

	t.Run("Directory Creation Error", func(t *testing.T) {
		// Create a file with the same name as the directory we want to create
		// This will cause MkdirAll to fail
		readOnlyDir := filepath.Join(tempDir, "readonly")
		err := os.MkdirAll(readOnlyDir, 0755)
		require.NoError(t, err)

		// Create a file that will conflict with directory creation
		conflictPath := filepath.Join(readOnlyDir, "conflict")
		err = os.WriteFile(conflictPath, []byte("test"), 0644)
		require.NoError(t, err)

		// Try to write metadata to a path that will conflict
		ticketInfo := &types.TicketInfo{
			KrbFilePath: "/tmp/krb5cc_test",
		}

		// This should fail because we're trying to create a directory at a path where a file exists
		err = WriteMetaDataJSON([]*types.TicketInfo{ticketInfo}, "conflict", readOnlyDir)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to create metadata directory")
	})
}
