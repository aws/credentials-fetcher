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

func TestValidateRequest(t *testing.T) {
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
		{
			name: "No credspec contents",
			request: &pb.CreateNonDomainJoinedKerberosLeaseRequest{
				Username:         "testuser",
				Password:         "testpassword",
				Domain:           "example.com",
				CredspecContents: []string{},
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create handler with minimal dependencies for validation test
			handler := &NonDomainJoinedKerberosHandler{
				krbFilesDir:       "/tmp/krb",
				awsSecretsManager: "test-secret",
				shellExecutor:     cmdexec.NewExecutor(),
			}

			// Call the method
			err := handler.validateRequest(tt.request)

			// Check the results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
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
	assert.Equal(t, "test-secret", handler.awsSecretsManager)
}

// Test for setupKerberosFileForTicket
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
	krbFilePath, err := handler.setupKerberosFileForTicket(ticketInfo)

	// Verify the results
	assert.NoError(t, err)
	assert.Equal(t, filepath.Join(tempDir, "test-lease-id", "testaccount", "krb5cc"), krbFilePath)
	assert.Equal(t, filepath.Join(tempDir, "test-lease-id", "testaccount", "krb5cc"), ticketInfo.KrbFilePath)

	// Verify that the directory and file were created
	_, err = os.Stat(filepath.Join(tempDir, "test-lease-id", "testaccount"))
	assert.NoError(t, err)
	_, err = os.Stat(filepath.Join(tempDir, "test-lease-id", "testaccount", "krb5cc"))
	assert.NoError(t, err)
}

// Test for cleanupKerberosFiles
func TestCleanupKerberosFiles(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Create a test file
	testFilePath := filepath.Join(tempDir, "test-file")
	file, err := os.Create(testFilePath)
	assert.NoError(t, err)
	file.Close()

	// Verify the file exists
	_, err = os.Stat(testFilePath)
	assert.NoError(t, err)

	// Call the function
	err = cleanupKerberosFiles(testFilePath)
	assert.NoError(t, err)

	// Verify the file was removed
	_, err = os.Stat(testFilePath)
	assert.True(t, os.IsNotExist(err))

	// Test with a non-existent file
	err = cleanupKerberosFiles(filepath.Join(tempDir, "non-existent-file"))
	assert.NoError(t, err) // Should not return an error for non-existent files
}
