package kerberos

import (
	"context"
	"errors"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// Test data - simplified to only what's needed
var validKlistOutput = `Ticket cache: FILE:/path/to/ticket
Default principal: user123@EXAMPLE.COM

Valid starting     Expires            Service principal
05/15/2023 09:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 05/22/2023 09:00:00
`

var missingPrincipalOutput = `Ticket cache: FILE:/path/to/ticket

Valid starting     Expires            Service principal
05/15/2023 09:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 05/22/2023 09:00:00
`

// MockExecutor mocks the cmdexec.Executor interface for testing
type MockExecutor struct {
	mock.Mock
}

func (m *MockExecutor) Execute(ctx context.Context, command string, args ...string) ([]byte, error) {
	callArgs := []interface{}{ctx, command}
	for _, arg := range args {
		callArgs = append(callArgs, arg)
	}
	ret := m.Called(callArgs...)
	return ret.Get(0).([]byte), ret.Error(1)
}

func (m *MockExecutor) ExecuteWithEnv(ctx context.Context, command string, env []string, args ...string) ([]byte, error) {
	callArgs := []interface{}{ctx, command, env}
	for _, arg := range args {
		callArgs = append(callArgs, arg)
	}
	ret := m.Called(callArgs...)
	return ret.Get(0).([]byte), ret.Error(1)
}

func (m *MockExecutor) ExecuteWithStdin(ctx context.Context, command string, stdin []byte, args ...string) ([]byte, error) {
	callArgs := []interface{}{ctx, command, stdin}
	for _, arg := range args {
		callArgs = append(callArgs, arg)
	}
	ret := m.Called(callArgs...)
	return ret.Get(0).([]byte), ret.Error(1)
}

func (m *MockExecutor) ExecuteWithStdinAndEnv(ctx context.Context, command string, stdin []byte, env []string, args ...string) ([]byte, error) {
	callArgs := []interface{}{ctx, command, stdin, env}
	for _, arg := range args {
		callArgs = append(callArgs, arg)
	}
	ret := m.Called(callArgs...)
	return ret.Get(0).([]byte), ret.Error(1)
}

func (m *MockExecutor) BuildCommand(command string, args ...string) string {
	callArgs := []interface{}{command}
	for _, arg := range args {
		callArgs = append(callArgs, arg)
	}
	ret := m.Called(callArgs...)
	return ret.String(0)
}

// Mock LDAP client for testing
type MockLdapClient struct {
	mock.Mock
}

func (m *MockLdapClient) FindDN(ctx context.Context, serviceAccount, baseDN, fqdn string) (string, error) {
	args := m.Called(ctx, serviceAccount, baseDN, fqdn)
	return args.String(0), args.Error(1)
}

func (m *MockLdapClient) SearchGMSAPassword(ctx context.Context, dn, fqdn string, executor interface{}) ([]byte, error) {
	args := m.Called(ctx, dn, fqdn, executor)
	return args.Get(0).([]byte), args.Error(1)
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	assert.NotNil(t, client, "Client should not be nil")
	assert.NotNil(t, client.shellExecutor, "Shell executor should not be nil")

	// Verify that the shell executor is of the expected type
	_, ok := client.shellExecutor.(cmdexec.Executor)
	assert.True(t, ok, "Shell executor should implement the Executor interface")
}

func TestGetTicket(t *testing.T) {
	testCases := []struct {
		name          string
		path          string
		mockOutput    []byte
		mockErr       error
		expectedError bool
	}{
		{
			name:          "Successful ticket retrieval",
			path:          "/path/to/ticket",
			mockOutput:    []byte(validKlistOutput),
			mockErr:       nil,
			expectedError: false,
		},
		{
			name:          "Klist command failure",
			path:          "/path/to/ticket",
			mockOutput:    []byte("Error: No credentials cache found"),
			mockErr:       errors.New("klist command failed"),
			expectedError: true,
		},
		{
			name:          "Missing principal in output",
			path:          "/path/to/ticket",
			mockOutput:    []byte(missingPrincipalOutput),
			mockErr:       nil,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock shell executor
			mockExecutor := new(MockExecutor)

			// Set up expectations
			mockExecutor.On("Execute",
				mock.Anything, // context
				"klist",       // command
				"-c", tc.path, // args
			).Return(tc.mockOutput, tc.mockErr)

			// Create a client with the mock executor
			client := &Client{
				shellExecutor: mockExecutor,
			}

			// Call GetTicket
			ticket, ticketInfo, err := client.GetTicket(tc.path)

			// Check results
			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, ticket, "Ticket should be nil on error")
				assert.Nil(t, ticketInfo, "TicketInfo should be nil on error")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.NotNil(t, ticket, "Ticket should not be nil")
				assert.NotEmpty(t, ticket.Principal, "Principal should not be empty")
				assert.Equal(t, tc.path, ticketInfo.KrbFilePath, "Ticket path should match")
			}

			// Verify that the mock was called as expected
			mockExecutor.AssertExpectations(t)
		})
	}
}

func TestCreateTicketUsingUsernamePassword(t *testing.T) {
	testCases := []struct {
		name          string
		domain        string
		username      string
		password      string
		mockOutput    []byte
		mockErr       error
		expectedError bool
	}{
		{
			name:          "Successful ticket creation",
			domain:        "example.com",
			username:      "testuser",
			password:      "password123",
			mockOutput:    []byte("Ticket successfully created"),
			mockErr:       nil,
			expectedError: false,
		},
		{
			name:          "Kinit command failure",
			domain:        "example.com",
			username:      "testuser",
			password:      "password123",
			mockOutput:    []byte("Kinit failed: invalid credentials"),
			mockErr:       errors.New("kinit command failed"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock shell executor
			mockExecutor := new(MockExecutor)

			// Set up expectations
			expectedPrincipal := tc.username + "@" + "EXAMPLE.COM"
			mockExecutor.On("ExecuteWithStdin",
				mock.Anything,            // context
				"kinit",                  // command
				[]byte(tc.password+"\n"), // stdin
				expectedPrincipal,        // args
			).Return(tc.mockOutput, tc.mockErr)

			// Create a client with the mock executor
			client := &Client{
				shellExecutor: mockExecutor,
			}

			// Call CreateTicketUsingUsernamePassword
			err := client.CreateTicketUsingUsernamePassword(tc.domain, tc.username, tc.password)

			// Check results
			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}

			// Verify that the mock was called as expected
			mockExecutor.AssertExpectations(t)
		})
	}
}

func TestCreateTicketForServiceAccount(t *testing.T) {
	testCases := []struct {
		name          string
		domain        string
		username      string
		password      string
		krbFilePath   string
		mockOutput    []byte
		mockErr       error
		expectedError bool
	}{
		{
			name:          "Successful service account ticket creation",
			domain:        "example.com",
			username:      "svc_account",
			password:      "svc_password",
			krbFilePath:   "/path/to/krb5cc_svc",
			mockOutput:    []byte("Ticket successfully created"),
			mockErr:       nil,
			expectedError: false,
		},
		{
			name:          "Kinit command failure for service account",
			domain:        "example.com",
			username:      "svc_account",
			password:      "svc_password",
			krbFilePath:   "/path/to/krb5cc_svc",
			mockOutput:    []byte("Kinit failed: invalid credentials"),
			mockErr:       errors.New("kinit command failed"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock shell executor
			mockExecutor := new(MockExecutor)

			// Set up expectations
			expectedPrincipal := tc.username + "@" + "EXAMPLE.COM"
			mockExecutor.On("ExecuteWithStdin",
				mock.Anything,            // context
				"kinit",                  // command
				[]byte(tc.password+"\n"), // stdin
				"-c", tc.krbFilePath,     // args
				expectedPrincipal, // args
			).Return(tc.mockOutput, tc.mockErr)

			// Create a client with the mock executor
			client := &Client{
				shellExecutor: mockExecutor,
			}

			// Call CreateTicketForServiceAccount
			ctx := context.Background()
			err := client.CreateTicketForServiceAccount(ctx, tc.domain, tc.username, tc.password, tc.krbFilePath)

			// Check results
			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}

			// Verify that the mock was called as expected
			mockExecutor.AssertExpectations(t)
		})
	}
}

func TestCreateTicketForGMSA(t *testing.T) {
	// Save original environment and restore after test
	originalEnv := os.Getenv("CF_GMSA_OU")
	defer os.Setenv("CF_GMSA_OU", originalEnv)

	// Save original functions and restore after test
	originalGetFQDNList := getFQDNListFunc
	defer func() {
		getFQDNListFunc = originalGetFQDNList
	}()

	testCases := []struct {
		name          string
		ticketInfo    *types.TicketInfo
		mockFQDNs     []string
		mockFQDNErr   error
		setEnvVar     bool
		expectedError bool
	}{
		{
			name: "Empty domain name",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:     nil,
			mockFQDNErr:   nil,
			setEnvVar:     false,
			expectedError: true,
		},
		{
			name: "Empty service account name",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:     nil,
			mockFQDNErr:   nil,
			setEnvVar:     false,
			expectedError: true,
		},
		{
			name: "Failed to get FQDN list",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:     nil,
			mockFQDNErr:   errors.New("failed to get FQDN list"),
			setEnvVar:     false,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variable if needed
			if tc.setEnvVar {
				os.Setenv("CF_GMSA_OU", "CN=Managed Service Accounts,DC=example,DC=com")
			} else {
				os.Setenv("CF_GMSA_OU", "")
			}

			// Create mocks
			mockExecutor := new(MockExecutor)

			// Mock the GetFQDNList function
			getFQDNListFunc = func(domain string) ([]string, error) {
				return tc.mockFQDNs, tc.mockFQDNErr
			}

			// Create a client with the mock executor
			client := &Client{
				shellExecutor: mockExecutor,
			}

			// Call CreateTicketForGMSA
			err := client.CreateTicketForGMSA(tc.ticketInfo)

			// Check results
			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}

			// Verify that the mock was called as expected
			mockExecutor.AssertExpectations(t)
		})
	}
}

// Test the validateGMSATicketInfo function
func TestValidateGMSATicketInfo(t *testing.T) {
	testCases := []struct {
		name          string
		ticketInfo    *types.TicketInfo
		expectedError bool
	}{
		{
			name: "Valid ticket info",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			expectedError: false,
		},
		{
			name: "Empty domain name",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			expectedError: true,
		},
		{
			name: "Empty service account name",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			client := NewClient()
			err := client.validateGMSATicketInfo(tc.ticketInfo)

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}
		})
	}
}

// Test the prepareGMSALDAPParameters function
func TestPrepareGMSALDAPParameters(t *testing.T) {
	// Save original functions and restore after test
	originalGetFQDNList := getFQDNListFunc
	defer func() {
		getFQDNListFunc = originalGetFQDNList
	}()

	// Save original environment and restore after test
	originalEnv := os.Getenv("CF_GMSA_OU")
	defer os.Setenv("CF_GMSA_OU", originalEnv)

	testCases := []struct {
		name          string
		ticketInfo    *types.TicketInfo
		mockFQDNs     []string
		mockFQDNErr   error
		setEnvVar     bool
		envValue      string
		expectedError bool
	}{
		{
			name: "Successful preparation",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:     []string{"dc1.example.com", "dc2.example.com"},
			mockFQDNErr:   nil,
			setEnvVar:     false,
			expectedError: false,
		},
		{
			name: "Failed to get FQDN list",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:     nil,
			mockFQDNErr:   errors.New("failed to get FQDN list"),
			setEnvVar:     false,
			expectedError: true,
		},
		{
			name: "With environment variable",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:     []string{"dc1.example.com", "dc2.example.com"},
			mockFQDNErr:   nil,
			setEnvVar:     true,
			envValue:      "CN=Managed Service Accounts,DC=example,DC=com",
			expectedError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variable if needed
			if tc.setEnvVar {
				os.Setenv("CF_GMSA_OU", tc.envValue)
			} else {
				os.Setenv("CF_GMSA_OU", "")
			}

			// Mock the GetFQDNList function
			getFQDNListFunc = func(domain string) ([]string, error) {
				return tc.mockFQDNs, tc.mockFQDNErr
			}

			client := NewClient()
			baseDN, fqdnList, err := client.prepareGMSALDAPParameters(tc.ticketInfo)

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Empty(t, baseDN, "BaseDN should be empty on error")
				assert.Nil(t, fqdnList, "FQDN list should be nil on error")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.NotEmpty(t, baseDN, "BaseDN should not be empty")
				assert.Equal(t, tc.mockFQDNs, fqdnList, "FQDN list should match")

				if tc.setEnvVar {
					assert.Equal(t, tc.envValue, tc.ticketInfo.DistinguishedName, "Distinguished name should be set from environment")
				}
			}
		})
	}
}

// Test the createKerberosTicket function
func TestCreateKerberosTicket(t *testing.T) {
	testCases := []struct {
		name          string
		ticketInfo    *types.TicketInfo
		password      []byte
		mockOutput    []byte
		mockErr       error
		expectedError bool
	}{
		{
			name: "Successfully create ticket",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			password:      []byte("password123"),
			mockOutput:    []byte("Ticket successfully created"),
			mockErr:       nil,
			expectedError: false,
		},
		{
			name: "Failed to create ticket",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			password:      []byte("password123"),
			mockOutput:    []byte("Kinit failed: invalid credentials"),
			mockErr:       errors.New("kinit command failed"),
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock shell executor
			mockExecutor := new(MockExecutor)

			// Set up expectations
			expectedPrincipal := tc.ticketInfo.ServiceAccountName + "@" + "EXAMPLE.COM"
			mockExecutor.On("ExecuteWithStdin",
				mock.Anything,                   // context
				"kinit",                         // command
				tc.password,                     // stdin
				"-c", tc.ticketInfo.KrbFilePath, // args
				"-V",
				expectedPrincipal,
			).Return(tc.mockOutput, tc.mockErr)

			// Create a client with the mock executor
			client := &Client{
				shellExecutor: mockExecutor,
			}

			// Call createKerberosTicket
			err := client.createKerberosTicket(context.Background(), tc.ticketInfo, tc.password)

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}

			// Verify that the mock was called as expected
			mockExecutor.AssertExpectations(t)
		})
	}
}

// Test GetTicketsFromMetadata function
func TestGetTicketsFromMetadata(t *testing.T) {
	// Save original function and restore after test
	originalReadMetadataJSON := readMetadataJSONFunc
	defer func() {
		readMetadataJSONFunc = originalReadMetadataJSON
	}()

	testCases := []struct {
		name             string
		metadataPath     string
		mockTicketInfos  []*types.TicketInfo
		mockReadErr      error
		mockGetTicketErr error
		expectedError    bool
	}{
		{
			name:         "Successfully get tickets from metadata",
			metadataPath: "/path/to/metadata.json",
			mockTicketInfos: []*types.TicketInfo{
				{
					ServiceAccountName: "svc1",
					DomainName:         "example.com",
					KrbFilePath:        "/path/to/krb5cc_svc1",
				},
			},
			mockReadErr:      nil,
			mockGetTicketErr: nil,
			expectedError:    false,
		},
		{
			name:             "Failed to read metadata file",
			metadataPath:     "/path/to/metadata.json",
			mockTicketInfos:  nil,
			mockReadErr:      errors.New("failed to read metadata file"),
			mockGetTicketErr: nil,
			expectedError:    true,
		},
		{
			name:             "Empty ticket info list",
			metadataPath:     "/path/to/metadata.json",
			mockTicketInfos:  []*types.TicketInfo{},
			mockReadErr:      nil,
			mockGetTicketErr: nil,
			expectedError:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Mock the ReadMetadataJSON function
			readMetadataJSONFunc = func(path string) ([]*types.TicketInfo, error) {
				assert.Equal(t, tc.metadataPath, path, "Metadata path should match")
				return tc.mockTicketInfos, tc.mockReadErr
			}

			// Create a mock shell executor
			mockExecutor := new(MockExecutor)

			// Create a client
			client := &Client{
				shellExecutor: mockExecutor,
			}

			// If we have ticket infos and no read error, set up expectations for GetTicket
			if tc.mockTicketInfos != nil && tc.mockReadErr == nil {
				for _, ticketInfo := range tc.mockTicketInfos {
					// Set up mock for Execute to return valid klist output
					mockExecutor.On("Execute",
						mock.Anything,                // context
						"klist",                      // command
						"-c", ticketInfo.KrbFilePath, // args
					).Return([]byte(validKlistOutput), tc.mockGetTicketErr)
				}
			}

			// Call GetTicketsFromMetadata
			tickets, ticketInfos, err := client.GetTicketsFromMetadata(tc.metadataPath)

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, tickets, "Tickets should be nil on error")
				assert.Nil(t, ticketInfos, "TicketInfos should be nil on error")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.NotNil(t, tickets, "Tickets should not be nil")
				assert.NotNil(t, ticketInfos, "TicketInfos should not be nil")
				assert.Equal(t, len(tc.mockTicketInfos), len(tickets), "Number of tickets should match")
				assert.Equal(t, len(tc.mockTicketInfos), len(ticketInfos), "Number of ticket infos should match")
			}

			// Verify that the mock was called as expected
			mockExecutor.AssertExpectations(t)
		})
	}
}
