package api

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.a2z.com/CredentialsFetcherV2/internal/auth/kerberos"
	"golang.a2z.com/CredentialsFetcherV2/internal/auth/ldap"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
)

// MockKerberosClient is a mock implementation of the Kerberos client
type MockKerberosClient struct {
	mock.Mock
}

func (m *MockKerberosClient) CreateTicketUsingUsernamePassword(username, password, domain string) error {
	args := m.Called(username, password, domain)
	return args.Error(0)
}

func (m *MockKerberosClient) CreateTicketForServiceAccount(ctx context.Context, domain, username, password, krbFilePath string) error {
	args := m.Called(ctx, domain, username, password, krbFilePath)
	return args.Error(0)
}

func (m *MockKerberosClient) CreateTicketForGMSA(ctx context.Context, domain, serviceAccount, dn, krbFilePath string, ldapClient *ldap.Client) error {
	args := m.Called(ctx, domain, serviceAccount, dn, krbFilePath, ldapClient)
	return args.Error(0)
}

// MockLDAPClient is a mock implementation of the LDAP client
type MockLDAPClient struct {
	mock.Mock
}

func (m *MockLDAPClient) SearchGMSAPassword(ctx context.Context, dn, fqdn string, executor ldap.LdapsearchExecutor) ([]byte, error) {
	args := m.Called(ctx, dn, fqdn, executor)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockLDAPClient) FindDN(ctx context.Context, gmsaAccountName, baseDN, fqdn string) (string, error) {
	args := m.Called(ctx, gmsaAccountName, baseDN, fqdn)
	return args.String(0), args.Error(1)
}

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
			// Create handler
			handler := &NonDomainJoinedKerberosHandler{
				krbFilesDir:       "/tmp/krb",
				awsSecretsManager: "test-secret",
				krbClient:         &kerberos.Client{},
				ldapClient:        &ldap.Client{},
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
