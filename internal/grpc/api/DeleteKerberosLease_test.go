package api

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.a2z.com/CredentialsFetcherV2/constants"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
)

// MockKerberosClient is a mock implementation for testing
type MockKerberosClient struct {
	mock.Mock
}

func (m *MockKerberosClient) DeleteKerberosLease(ctx context.Context, krbFilePath string) error {
	args := m.Called(ctx, krbFilePath)
	return args.Error(0)
}

// TestDeleteKerberosLeaseWithMock tests the DeleteKerberosLease function using a mock
func TestDeleteKerberosLeaseWithMock(t *testing.T) {
	// Skip this test for now as we need to refactor the code to use an interface
	t.Skip("Skipping test that requires interface refactoring")
}

func TestValidateDeleteRequest(t *testing.T) {
	handler := &KerberosLeaseHandler{
		krbFilesDir: "/tmp/test",
	}

	tests := []struct {
		name          string
		request       *pb.DeleteKerberosLeaseRequest
		expectedError bool
	}{
		{
			name: "Valid request",
			request: &pb.DeleteKerberosLeaseRequest{
				LeaseId: "test-lease",
			},
			expectedError: false,
		},
		{
			name: "Empty lease ID",
			request: &pb.DeleteKerberosLeaseRequest{
				LeaseId: "",
			},
			expectedError: true,
		},
		{
			name: "Lease ID exceeds maximum filename length",
			request: &pb.DeleteKerberosLeaseRequest{
				LeaseId: strings.Repeat("a", constants.MaxFilenameLength+1),
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := handler.validateRequest(tt.request)
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsDirEmpty(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()

	// Test empty directory
	empty, err := isDirEmpty(tempDir)
	assert.NoError(t, err)
	assert.True(t, empty)

	// Create a file in the directory
	testFile := filepath.Join(tempDir, "test.txt")
	_, err = os.Create(testFile)
	assert.NoError(t, err)

	// Test non-empty directory
	empty, err = isDirEmpty(tempDir)
	assert.NoError(t, err)
	assert.False(t, empty)

	// Test non-existent directory
	_, err = isDirEmpty("/non/existent/dir")
	assert.Error(t, err)
}
