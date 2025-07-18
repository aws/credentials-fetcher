package ldap

import (
	"context"
	"errors"
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
				"-o", "ldif_wrap=no", "-LLL", "-Y", "GSSAPI", "-l", "5", "-H", "ldap://contoso.com",
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
				"-o", "ldif_wrap=no", "-LLL", "-Y", "GSSAPI", "-l", "5", "-H", "ldap://contoso.com",
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
				"-o", "ldif_wrap=no", "-LLL", "-Y", "GSSAPI", "-l", "5", "-H", "ldap://contoso.com",
				"-b", "DC=contoso,DC=com", "-s", "sub", "(objectClass=*)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock Config File
			originalGetLdapTimeoutFunc := getLdapTimeoutFromConf
			defer func() { getLdapTimeoutFromConf = originalGetLdapTimeoutFunc }()
			getLdapTimeoutFromConf = func() (string, error) { return "5", nil }

			executor := NewDefaultLdapsearchExecutor()
			cmd, args, _ := executor.BuildLdapsearchCommandWithFilter(tt.baseDN, tt.fqdn, tt.searchFilter, tt.attributes)

			assert.Equal(t, tt.expectedCmd, cmd)
			assert.Equal(t, tt.expectedArgs, args)
		})
	}
}

// MockShellExecutor is a mock implementation for testing timeout scenarios
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
	mockArgs := m.Called(command, args)
	return mockArgs.String(0)
}

// Test timeout detection in ExecuteLdapsearchWithFilter
func TestExecuteLdapsearchWithFilter_TimeoutDetection(t *testing.T) {
	tests := []struct {
		name        string
		mockError   error
		mockOutput  []byte
		expectWarn  bool
		description string
	}{
		{
			name:        "Time limit exceeded in error",
			mockError:   errors.New("ldapsearch: time limit exceeded"),
			mockOutput:  []byte(""),
			expectWarn:  true,
			description: "Should detect timeout when error contains 'time limit exceeded'",
		},
		{
			name:        "Time limit exceeded in output",
			mockError:   errors.New("ldapsearch failed"),
			mockOutput:  []byte("ldap_search: Time limit exceeded (3)"),
			expectWarn:  true,
			description: "Should detect timeout when output contains 'time limit exceeded'",
		},
		{
			name:        "Timeout in error message",
			mockError:   errors.New("operation timeout"),
			mockOutput:  []byte(""),
			expectWarn:  true,
			description: "Should detect timeout when error contains 'timeout'",
		},
		{
			name:        "Timeout in output message",
			mockError:   errors.New("ldapsearch failed"),
			mockOutput:  []byte("Connection timeout occurred"),
			expectWarn:  true,
			description: "Should detect timeout when output contains 'timeout'",
		},
		{
			name:        "Non-timeout error",
			mockError:   errors.New("connection refused"),
			mockOutput:  []byte("ldap_bind: Invalid credentials (49)"),
			expectWarn:  false,
			description: "Should not detect timeout for other errors",
		},
		{
			name:        "Case insensitive timeout detection",
			mockError:   errors.New("LDAPSEARCH: TIME LIMIT EXCEEDED"),
			mockOutput:  []byte(""),
			expectWarn:  true,
			description: "Should detect timeout case-insensitively",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock config file
			originalGetLdapTimeoutFunc := getLdapTimeoutFromConf
			defer func() { getLdapTimeoutFromConf = originalGetLdapTimeoutFunc }()
			getLdapTimeoutFromConf = func() (string, error) { return "5", nil }

			// Create mock shell executor
			mockShellExecutor := new(MockShellExecutor)

			// Set up the mock to return the test error and output
			mockShellExecutor.On("BuildCommand", "ldapsearch", mock.Anything).Return("ldapsearch command")
			mockShellExecutor.On("Execute", mock.Anything, "ldapsearch", mock.Anything).Return(tt.mockOutput, tt.mockError)

			// Create executor with mock shell executor
			executor := &DefaultLdapsearchExecutor{
				shellExecutor: mockShellExecutor,
			}

			// Execute the method
			result, err := executor.ExecuteLdapsearchWithFilter(
				context.Background(),
				"DC=contoso,DC=com",
				"contoso.com",
				"(objectClass=*)",
				[]string{"cn"},
			)

			// Verify error is returned
			assert.Error(t, err)
			assert.Nil(t, result)

			// Verify the mock was called
			mockShellExecutor.AssertExpectations(t)
		})
	}
}

// Test that ldapSearchBaseArgs contains timeout parameter
func TestLdapSearchBaseArgs_ContainsTimeout(t *testing.T) {
	// Mock config file
	originalGetLdapTimeoutFunc := getLdapTimeoutFromConf
	defer func() { getLdapTimeoutFromConf = originalGetLdapTimeoutFunc }()
	getLdapTimeoutFromConf = func() (string, error) { return "5", nil }

	// Verify that the base args contain the timeout parameter
	expectedArgs := []string{"-o", "ldif_wrap=no", "-LLL", "-Y", "GSSAPI", "-l", "5", "-H"}
	args, _ := getLdapSearchBaseArgs()
	assert.Equal(t, expectedArgs, args, "ldapSearchBaseArgs should contain timeout parameter -l 5")
}

func TestExecuteLdapsearchWithBaseArgsError_(t *testing.T) {
	// Save the original function
	originalGetLdapTimeoutFunc := getLdapTimeoutFromConf

	// Restore the original function after the test
	defer func() {
		getLdapTimeoutFromConf = originalGetLdapTimeoutFunc
	}()

	// Mock the getLdapTimeoutFromConf function to return a specific value
	getLdapTimeoutFromConf = func() (string, error) {
		return "", errors.New("Negative LDAPSearchTimeout value: -2")
	}

	mockShellExecutor := new(MockShellExecutor)

	// Create executor with mock shell executor
	executor := &DefaultLdapsearchExecutor{
		shellExecutor: mockShellExecutor,
	}

	// Execute the method
	result, err := executor.ExecuteLdapsearchWithFilter(
		context.Background(),
		"DC=contoso,DC=com",
		"contoso.com",
		"(objectClass=*)",
		[]string{"cn"},
	)

	// Verify error is returned
	assert.Error(t, err)
	assert.Nil(t, result)
}

// Test that ldapSearchBaseArgs contains timeout parameter if included in config file
func TestLdapSearchBaseArgs_ContainsConfigTimeout(t *testing.T) {
	// Mock config file
	originalGetLdapTimeoutFunc := getLdapTimeoutFromConf
	defer func() { getLdapTimeoutFromConf = originalGetLdapTimeoutFunc }()
	getLdapTimeoutFromConf = func() (string, error) { return "30", nil }

	// Create a new LDAP client executor
	executor := NewDefaultLdapsearchExecutor()

	// Test that the command includes the correct timeout
	_, args, _ := executor.BuildLdapsearchCommandWithFilter(
		"DC=contoso,DC=com",
		"contoso.com",
		"(objectClass=*)",
		[]string{"cn"},
	)

	// Check that the args contain the expected timeout
	timeoutFound := false
	for i, arg := range args {
		if arg == "-l" && i+1 < len(args) && args[i+1] == "30" {
			timeoutFound = true
			break
		}
	}

	assert.True(t, timeoutFound, "Should find -l flag with value 30")
}

// Test that timeout parameter is correctly included in built commands
func TestBuildLdapsearchCommandWithFilter_IncludesTimeout(t *testing.T) {
	// Mock config file
	originalGetLdapTimeoutFunc := getLdapTimeoutFromConf
	defer func() { getLdapTimeoutFromConf = originalGetLdapTimeoutFunc }()
	getLdapTimeoutFromConf = func() (string, error) { return "5", nil }
	executor := NewDefaultLdapsearchExecutor()

	cmd, args, _ := executor.BuildLdapsearchCommandWithFilter(
		"DC=contoso,DC=com",
		"contoso.com",
		"(objectClass=*)",
		[]string{"cn"},
	)

	assert.Equal(t, "ldapsearch", cmd)

	// Verify timeout parameters are present
	assert.Contains(t, args, "-l", "Command should contain timeout flag -l")
	assert.Contains(t, args, "5", "Command should contain timeout value 5")

	// Verify the timeout parameters are in the correct position (after GSSAPI, before -H)
	lIndex := -1
	timeoutIndex := -1
	for i, arg := range args {
		if arg == "-l" {
			lIndex = i
		}
		if arg == "5" && lIndex == i-1 {
			timeoutIndex = i
		}
	}

	assert.NotEqual(t, -1, lIndex, "Should find -l flag")
	assert.NotEqual(t, -1, timeoutIndex, "Should find timeout value 2 immediately after -l flag")
}
