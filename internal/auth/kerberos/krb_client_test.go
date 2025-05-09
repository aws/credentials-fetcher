package kerberos

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.a2z.com/CredentialsFetcherV2/constants"
)

// Test data
var validKlistCompactOutput = `Ticket cache: FILE:/path/to/ticket
Default principal: user123@EXAMPLE.COM

Valid starting     Expires            Service principal
05/15/2023 09:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 05/22/2023 09:00:00
`

var validKlistMultilineOutput = `Ticket cache: FILE:/path/to/ticket
Default principal: user123@EXAMPLE.COM

Valid starting     Expires            Service principal
05/15/2023 09:00:00
                 05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 05/22/2023 09:00:00
`

var validKlistMachineOutput = `Ticket cache: FILE:/path/to/ticket
Default principal: machine$@EXAMPLE.COM

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

// Helper function to parse time strings
func parseTime(timeStr string) time.Time {
	t, _ := time.Parse(constants.KlistDateTimeFormat, timeStr)
	return t
}

func TestCreateTicketForGMSA(t *testing.T) {
	// Save original environment and restore after test
	originalEnv := os.Getenv("CF_GMSA_OU")
	defer os.Setenv("CF_GMSA_OU", originalEnv)

	testCases := []struct {
		name                string
		ticketInfo          *types.TicketInfo
		mockFQDNs           []string
		mockFQDNErr         error
		mockDN              string
		mockDNErr           error
		mockPassword        []byte
		mockPasswordErr     error
		mockKinitOutput     []byte
		mockKinitErr        error
		setEnvVar           bool
		expectedError       bool
		expectedKinitCalled bool
	}{
		{
			name: "Successful gMSA ticket creation",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				DistinguishedName:  "CN=gmsa_account,CN=Managed Service Accounts,DC=example,DC=com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:           []string{"dc1.example.com"},
			mockFQDNErr:         nil,
			mockDN:              "CN=gmsa_account,CN=Managed Service Accounts,DC=example,DC=com",
			mockDNErr:           nil,
			mockPassword:        []byte("gmsa_password"),
			mockPasswordErr:     nil,
			mockKinitOutput:     []byte("Ticket successfully created"),
			mockKinitErr:        nil,
			setEnvVar:           false,
			expectedError:       false,
			expectedKinitCalled: true,
		},
		{
			name: "Empty domain name",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:           nil,
			mockFQDNErr:         nil,
			mockDN:              "",
			mockDNErr:           nil,
			mockPassword:        nil,
			mockPasswordErr:     nil,
			mockKinitOutput:     nil,
			mockKinitErr:        nil,
			setEnvVar:           false,
			expectedError:       true,
			expectedKinitCalled: false,
		},
		{
			name: "Empty service account name",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:           nil,
			mockFQDNErr:         nil,
			mockDN:              "",
			mockDNErr:           nil,
			mockPassword:        nil,
			mockPasswordErr:     nil,
			mockKinitOutput:     nil,
			mockKinitErr:        nil,
			setEnvVar:           false,
			expectedError:       true,
			expectedKinitCalled: false,
		},
		{
			name: "Failed to get FQDN list",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:           nil,
			mockFQDNErr:         errors.New("failed to get FQDN list"),
			mockDN:              "",
			mockDNErr:           nil,
			mockPassword:        nil,
			mockPasswordErr:     nil,
			mockKinitOutput:     nil,
			mockKinitErr:        nil,
			setEnvVar:           false,
			expectedError:       true,
			expectedKinitCalled: false,
		},
		{
			name: "Failed to find password for any FQDN",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				DistinguishedName:  "CN=gmsa_account,CN=Managed Service Accounts,DC=example,DC=com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:           []string{"dc1.example.com"},
			mockFQDNErr:         nil,
			mockDN:              "CN=gmsa_account,CN=Managed Service Accounts,DC=example,DC=com",
			mockDNErr:           nil,
			mockPassword:        nil,
			mockPasswordErr:     errors.New("failed to find password"),
			mockKinitOutput:     nil,
			mockKinitErr:        nil,
			setEnvVar:           false,
			expectedError:       true,
			expectedKinitCalled: false,
		},
		{
			name: "Kinit command failure",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				DistinguishedName:  "CN=gmsa_account,CN=Managed Service Accounts,DC=example,DC=com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:           []string{"dc1.example.com"},
			mockFQDNErr:         nil,
			mockDN:              "CN=gmsa_account,CN=Managed Service Accounts,DC=example,DC=com",
			mockDNErr:           nil,
			mockPassword:        []byte("gmsa_password"),
			mockPasswordErr:     nil,
			mockKinitOutput:     []byte("Kinit failed"),
			mockKinitErr:        errors.New("kinit command failed"),
			setEnvVar:           false,
			expectedError:       true,
			expectedKinitCalled: true,
		},
		{
			name: "Use environment variable for DN",
			ticketInfo: &types.TicketInfo{
				ServiceAccountName: "gmsa_account",
				DomainName:         "example.com",
				KrbFilePath:        "/path/to/krb5cc_gmsa",
			},
			mockFQDNs:           []string{"dc1.example.com"},
			mockFQDNErr:         nil,
			mockDN:              "",
			mockDNErr:           errors.New("failed to find DN"),
			mockPassword:        []byte("gmsa_password"),
			mockPasswordErr:     nil,
			mockKinitOutput:     []byte("Ticket successfully created"),
			mockKinitErr:        nil,
			setEnvVar:           true,
			expectedError:       false,
			expectedKinitCalled: true,
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
			mockLdapClient := new(MockLdapClient)
			
			// Save original functions and restore after test
			originalGetFQDNList := grpc_utils.GetFQDNList
			originalNewClient := ldap.NewClient
			
			// Mock the GetFQDNList function
			grpc_utils.GetFQDNList = func(domain string) ([]string, error) {
				return tc.mockFQDNs, tc.mockFQDNErr
			}
			
			// Mock the ldap.NewClient function
			ldap.NewClient = func() *ldap.Client {
				return &ldap.Client{}
			}
			
			// Set up expectations for FindDN if needed
			if tc.mockDN != "" || tc.mockDNErr != nil {
				mockLdapClient.On("FindDN", 
					mock.Anything, // context
					tc.ticketInfo.ServiceAccountName,
					mock.Anything, // baseDN
					tc.mockFQDNs[0],
				).Return(tc.mockDN, tc.mockDNErr)
			}
			
			// Set up expectations for SearchGMSAPassword
			if len(tc.mockFQDNs) > 0 {
				mockLdapClient.On("SearchGMSAPassword",
					mock.Anything, // context
					mock.Anything, // DN
					tc.mockFQDNs[0],
					mock.Anything, // executor
				).Return(tc.mockPassword, tc.mockPasswordErr)
			}
			
			// Set up expectations for kinit command if expected
			if tc.expectedKinitCalled {
				expectedPrincipal := tc.ticketInfo.ServiceAccountName + "@" + "EXAMPLE.COM"
				mockExecutor.On("ExecuteWithStdin", 
					mock.Anything, // context
					"kinit",       // command
					tc.mockPassword, // stdin
					"-c", tc.ticketInfo.KrbFilePath, // args
					"-V",
					expectedPrincipal, // args
				).Return(tc.mockKinitOutput, tc.mockKinitErr)
			}

			// Create a client with the mock executor
			client := &Client{
				shellExecutor: mockExecutor,
			}

			// Restore original functions after test
			defer func() {
				grpc_utils.GetFQDNList = originalGetFQDNList
				ldap.NewClient = originalNewClient
			}()

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
			mockLdapClient.AssertExpectations(t)
		})
	}
}

// MockLdapClient mocks the LDAP client for testing
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
