package ldap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockLdapsearchExecutor is a mock implementation of LdapsearchExecutor
type MockLdapsearchExecutor struct {
	mock.Mock
}

func (m *MockLdapsearchExecutor) ExecuteLdapsearchWithFilter(ctx context.Context, baseDN, fqdn, searchFilter string, attributes []string) ([]byte, error) {
	args := m.Called(ctx, baseDN, fqdn, searchFilter, attributes)
	return args.Get(0).([]byte), args.Error(1)
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	assert.NotNil(t, client)
}

func TestNewDefaultLdapsearchExecutor(t *testing.T) {
	executor := NewDefaultLdapsearchExecutor()
	assert.NotNil(t, executor)
}

func TestSearchGMSAPassword(t *testing.T) {
	tests := []struct {
		name           string
		dn             string
		fqdn           string
		mockOutput     []byte
		mockError      error
		expectedOutput []byte
		expectedError  bool
	}{
		{
			name:           "Successful password retrieval",
			dn:             "CN=WebApp01,OU=MYOU,OU=Users,OU=contoso,DC=contoso,DC=com",
			fqdn:           "contoso.com",
			mockOutput:     []byte("msDS-ManagedPassword:: AAAAAAAAAAAA"),
			mockError:      nil,
			expectedOutput: []byte("msDS-ManagedPassword:: AAAAAAAAAAAA"),
			expectedError:  false,
		},
		{
			name:           "ldapsearch command failure",
			dn:             "CN=NonExistent,DC=contoso,DC=com",
			fqdn:           "contoso.com",
			mockOutput:     []byte{},
			mockError:      errors.New("ldapsearch failed with exit code 1"),
			expectedOutput: nil,
			expectedError:  true,
		},
		{
			name:           "Empty DN",
			dn:             "",
			fqdn:           "contoso.com",
			mockOutput:     []byte{},
			mockError:      errors.New("invalid empty DN"),
			expectedOutput: nil,
			expectedError:  true,
		},
		{
			name:           "Empty FQDN",
			dn:             "CN=WebApp01,DC=contoso,DC=com",
			fqdn:           "",
			mockOutput:     []byte{},
			mockError:      errors.New("invalid empty FQDN"),
			expectedOutput: nil,
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a mock executor
			mockExecutor := new(MockLdapsearchExecutor)
			mockExecutor.On("ExecuteLdapsearchWithFilter", mock.Anything, tt.dn, tt.fqdn, "(objectClass=msDS-GroupManagedServiceAccount)", []string{"msDS-ManagedPassword", "-N"}).
				Return(tt.mockOutput, tt.mockError)

			// Create a client
			client := NewClient()

			// Call the method
			result, err := client.SearchGMSAPassword(context.Background(), tt.dn, tt.fqdn, mockExecutor)

			// Check the results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedOutput, result)
			}

			// Verify that the mocks were called as expected
			mockExecutor.AssertExpectations(t)
		})
	}
}

func TestSearchGMSAPasswordWithNilExecutor(t *testing.T) {
	client := NewClient()
	_, err := client.SearchGMSAPassword(context.Background(), "test-dn", "test-fqdn", nil)
	assert.Error(t, err) // Should fail because the default executor will try to run a real ldapsearch command
}

// Mock shell executor for testing
type mockShellExecutor struct {
	mockExecutor *MockLdapsearchExecutor
}

func (m *mockShellExecutor) Execute(ctx context.Context, command string, args ...string) ([]byte, error) {
	return []byte{}, nil
}

func (m *mockShellExecutor) ExecuteWithEnv(ctx context.Context, command string, env []string, args ...string) ([]byte, error) {
	return []byte{}, nil
}

func (m *mockShellExecutor) ExecuteWithStdin(ctx context.Context, command string, stdin []byte, args ...string) ([]byte, error) {
	return []byte{}, nil
}

func (m *mockShellExecutor) ExecuteWithStdinAndEnv(ctx context.Context, command string, stdin []byte, env []string, args ...string) ([]byte, error) {
	return []byte{}, nil
}

func (m *mockShellExecutor) BuildCommand(command string, args ...string) string {
	return command + " " + strings.Join(args, " ")
}

// Test for BuildLdapsearchCommandWithFilter
func TestBuildLdapsearchCommandWithFilter(t *testing.T) {
	tests := []struct {
		name         string
		baseDN       string
		fqdn         string
		searchFilter string
		attributes   []string
		expectedCmd  string
		expectedArgs []string
	}{
		{
			name:         "Basic search",
			baseDN:       "DC=contoso,DC=com",
			fqdn:         "contoso.com",
			searchFilter: "(objectClass=msDS-GroupManagedServiceAccount)",
			attributes:   []string{"msDS-ManagedPassword"},
			expectedCmd:  "ldapsearch",
			expectedArgs: []string{
				"-o", "ldif_wrap=no", "-LLL", "-Y", "GSSAPI", "-H", "ldap://contoso.com",
				"-b", "DC=contoso,DC=com", "-s", "sub", "(objectClass=msDS-GroupManagedServiceAccount)",
				"msDS-ManagedPassword",
			},
		},
		{
			name:         "Multiple attributes",
			baseDN:       "DC=contoso,DC=com",
			fqdn:         "contoso.com",
			searchFilter: "(sAMAccountName=WebApp01$)",
			attributes:   []string{"distinguishedName", "objectClass"},
			expectedCmd:  "ldapsearch",
			expectedArgs: []string{
				"-o", "ldif_wrap=no", "-LLL", "-Y", "GSSAPI", "-H", "ldap://contoso.com",
				"-b", "DC=contoso,DC=com", "-s", "sub", "(sAMAccountName=WebApp01$)",
				"distinguishedName", "objectClass",
			},
		},
		{
			name:         "No attributes",
			baseDN:       "DC=contoso,DC=com",
			fqdn:         "contoso.com",
			searchFilter: "(objectClass=*)",
			attributes:   []string{},
			expectedCmd:  "ldapsearch",
			expectedArgs: []string{
				"-o", "ldif_wrap=no", "-LLL", "-Y", "GSSAPI", "-H", "ldap://contoso.com",
				"-b", "DC=contoso,DC=com", "-s", "sub", "(objectClass=*)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := NewDefaultLdapsearchExecutor()
			cmd, args := executor.BuildLdapsearchCommandWithFilter(tt.baseDN, tt.fqdn, tt.searchFilter, tt.attributes)

			assert.Equal(t, tt.expectedCmd, cmd)
			assert.Equal(t, tt.expectedArgs, args)
		})
	}
}
