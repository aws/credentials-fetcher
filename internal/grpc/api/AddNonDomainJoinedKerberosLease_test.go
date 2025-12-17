package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// MockShellExecutor is a mock implementation of cmdexec.Executor
type MockShellExecutor struct {
	mock.Mock
}

func (m *MockShellExecutor) Execute(ctx context.Context, command string, args ...string) ([]byte, error) {
	mockArgs := m.Called(ctx, command, args)
	return mockArgs.Get(0).([]byte), mockArgs.Error(1)
}

func (m *MockShellExecutor) ExecuteWithEnv(ctx context.Context, command string, env []string, args ...string) ([]byte, error) {
	mockArgs := m.Called(ctx, command, env, args)
	return mockArgs.Get(0).([]byte), mockArgs.Error(1)
}

func (m *MockShellExecutor) ExecuteWithStdin(ctx context.Context, command string, stdin []byte, args ...string) ([]byte, error) {
	mockArgs := m.Called(ctx, command, stdin, args)
	return mockArgs.Get(0).([]byte), mockArgs.Error(1)
}

func (m *MockShellExecutor) ExecuteWithStdinAndEnv(ctx context.Context, command string, stdin []byte, env []string, args ...string) ([]byte, error) {
	mockArgs := m.Called(ctx, command, stdin, env, args)
	return mockArgs.Get(0).([]byte), mockArgs.Error(1)
}

func (m *MockShellExecutor) BuildCommand(command string, args ...string) string {
	return command + " " + strings.Join(args, " ")
}

func TestValidateCredentials(t *testing.T) {
	tests := []struct {
		name          string
		request       *pb.CreateNonDomainJoinedKerberosLeaseRequest
		expectedError bool
	}{
		{
			name: "Valid request",
			request: &pb.CreateNonDomainJoinedKerberosLeaseRequest{
				Username:         "testuser",
				Password:         "testpassword",
				Domain:           "example.com",
				CredspecContents: []string{"credspec1", "credspec2"},
			},
			expectedError: false,
		},
		{
			name: "Missing username",
			request: &pb.CreateNonDomainJoinedKerberosLeaseRequest{
				Username:         "",
				Password:         "testpassword",
				Domain:           "example.com",
				CredspecContents: []string{"credspec1"},
			},
			expectedError: true,
		},
		{
			name: "Missing password",
			request: &pb.CreateNonDomainJoinedKerberosLeaseRequest{
				Username:         "testuser",
				Password:         "",
				Domain:           "example.com",
				CredspecContents: []string{"credspec1"},
			},
			expectedError: true,
		},
		{
			name: "Missing domain",
			request: &pb.CreateNonDomainJoinedKerberosLeaseRequest{
				Username:         "testuser",
				Password:         "testpassword",
				Domain:           "",
				CredspecContents: []string{"credspec1"},
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler with minimal dependencies for validation test
			handler := &NonDomainJoinedKerberosHandler{
				krbFilesDir:     "/tmp/krb",
				awsSMSecretName: "test-secret",
				shellExecutor:   cmdexec.NewExecutor(),
			}

			// Call the method
			err := handler.ValidateCredentials(tt.request.Username, tt.request.Password, tt.request.Domain)

			// Check the results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				// For the "No_credspec_contents" test case, we need to skip the assertion
				// since ValidateCredentials doesn't check for empty credspec contents
				if tt.name == "No_credspec_contents" {
					// This test case is now obsolete since we're testing ValidateCredentials
					// which doesn't check for empty credspec contents
					t.Skip("Skipping this test case as ValidateCredentials doesn't check for empty credspec contents")
				} else {
					assert.NoError(t, err)
				}
			}
		})
	}
}

// Test for NewNonDomainJoinedKerberosHandler
func TestNewNonDomainJoinedKerberosHandler(t *testing.T) {
	// Call the function with minimal dependencies
	handler := NewNonDomainJoinedKerberosHandler(
		"/tmp/krb",
		"test-secret",
		nil,
		nil,
		cmdexec.NewExecutor(),
	)

	// Verify the handler was created correctly
	assert.NotNil(t, handler)
	assert.Equal(t, "/tmp/krb", handler.krbFilesDir)
	assert.Equal(t, "test-secret", handler.awsSMSecretName)
}

// Test for SetupKerberosFileForTicket
func TestSetupKerberosFileForTicket(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a mock handler
	handler := &NonDomainJoinedKerberosHandler{
		krbFilesDir: tempDir,
	}

	// Create a ticket info object
	ticketInfo := &types.TicketInfo{
		KrbFilePath:        filepath.Join(tempDir, "test-lease-id", "testaccount"),
		ServiceAccountName: "testaccount",
		DomainName:         "example.com",
	}

	// Call the function
	krbFilePath, err := handler.SetupKerberosFileForTicket(ticketInfo)

	// Verify the results
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(tempDir, "test-lease-id", "testaccount"), krbFilePath)
	assert.Equal(t, filepath.Join(tempDir, "test-lease-id", "testaccount", "krb5cc"), ticketInfo.KrbFilePath)

	// Verify that the directory and file were created
	_, err = os.Stat(filepath.Join(tempDir, "test-lease-id", "testaccount"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(tempDir, "test-lease-id", "testaccount", "krb5cc"))
	assert.NoError(t, err)
}

// Test for CleanupKerberosFiles
func TestCleanupKerberosFiles(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a test file
	testFilePath := filepath.Join(tempDir, "test-file")
	file, err := os.Create(testFilePath)
	assert.NoError(t, err)
	err = file.Close()
	if err != nil {
		return
	}

	// Create a handler
	handler := &NonDomainJoinedKerberosHandler{
		krbFilesDir: tempDir,
	}

	// Verify the file exists
	_, err = os.Stat(testFilePath)
	assert.NoError(t, err)

	// Call the function
	err = handler.CleanupKerberosFiles(testFilePath)
	assert.NoError(t, err)

	// Verify the file was removed
	_, err = os.Stat(testFilePath)
	assert.True(t, os.IsNotExist(err))

	// Test with a non-existent file
	err = handler.CleanupKerberosFiles(filepath.Join(tempDir, "non-existent-file"))
	assert.NoError(t, err) // Should not return an error for non-existent files
}

func TestProcessCredentialSpecs_DomainJoinedDetection(t *testing.T) {
	handler := NewNonDomainJoinedKerberosHandler("/tmp/krb", "test-secret", nil, nil, cmdexec.NewExecutor())

	tests := []struct {
		name          string
		credspecs     []string
		username      string
		leaseID       string
		expectError   bool
		errorContains string
	}{
		{
			name: "Valid non-domain-joined credspec",
			credspecs: []string{`{
				"DomainJoinConfig": {
					"Sid": "S-1-5-21-123456789-123456789-123456789",
					"MachineAccountName": "WebApp01",
					"Guid": "12345678-1234-1234-1234-123456789012",
					"DnsName": "example.com",
					"NetBiosName": "EXAMPLE"
				},
				"ActiveDirectoryConfig": {
					"GroupManagedServiceAccounts": [
						{
							"Name": "WebApp01",
							"Scope": "example.com"
						}
					],
					"HostAccountConfig": {
						"PluginGUID": "12345678-1234-1234-1234-123456789012",
						"PluginInput": {
							"CredentialArn": "arn:aws:secretsmanager:us-west-2:123456789012:secret:example-secret"
						},
						"PortableCcgVersion": "1"
					}
				}
			}`},
			username:    "testuser",
			leaseID:     "test-lease",
			expectError: false,
		},
		{
			name: "Domain-joined credspec (empty CredentialArn)",
			credspecs: []string{`{
				"DomainJoinConfig": {
					"Sid": "S-1-5-21-123456789-123456789-123456789",
					"MachineAccountName": "WebApp01",
					"Guid": "12345678-1234-1234-1234-123456789012",
					"DnsName": "example.com",
					"NetBiosName": "EXAMPLE"
				},
				"ActiveDirectoryConfig": {
					"GroupManagedServiceAccounts": [
						{
							"Name": "WebApp01",
							"Scope": "example.com"
						}
					]
				}
			}`},
			username:      "testuser",
			leaseID:       "test-lease",
			expectError:   true,
			errorContains: "domain-joined credential spec or environment detected but non-domain-joined API was invoked",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ticketInfoList, err := handler.ProcessCredentialSpecs(tt.credspecs, tt.username, tt.leaseID)

			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorContains)
				assert.Nil(t, ticketInfoList)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, ticketInfoList)
			}
		})
	}
}
