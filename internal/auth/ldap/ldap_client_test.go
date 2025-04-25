package ldap

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// MockLdapsearchExecutor mocks the LdapsearchExecutor interface for testing
type MockLdapsearchExecutor struct {
	Output         []byte
	Err            error
	CalledWithDN   string
	CalledWithFQDN string
	CalledCount    int
}

func (m *MockLdapsearchExecutor) executeLdapsearch(ctx context.Context, dn, fqdn string) ([]byte, error) {
	m.CalledWithDN = dn
	m.CalledWithFQDN = fqdn
	m.CalledCount++
	return m.Output, m.Err
}

func (m *MockLdapsearchExecutor) buildLdapsearchCommand(dn, fqdn string) (string, []string) {
	return "mock-ldapsearch", []string{"-b", dn, "-s", "sub", "filter", "msDS-ManagedPassword", "-N"}
}

func TestNewClient(t *testing.T) {
	client := NewClient()
	assert.NotNil(t, client, "NewClient should return a non-nil client")
	assert.IsType(t, &Client{}, client, "NewClient should return a *Client")
}

func TestSearchGMSAPassword(t *testing.T) {
	testCases := []struct {
		name           string
		dn             string
		fqdn           string
		mockOutput     []byte
		mockErr        error
		expectedOutput []byte
		expectError    bool
		errorContains  string
	}{
		{
			name:           "Successful password retrieval",
			dn:             "CN=WebApp01,OU=MYOU,OU=Users,OU=contoso,DC=contoso,DC=com",
			fqdn:           "contoso.com",
			mockOutput:     []byte("msDS-ManagedPassword:: ABCDEF123456"),
			mockErr:        nil,
			expectedOutput: []byte("msDS-ManagedPassword:: ABCDEF123456"),
			expectError:    false,
		},
		{
			name:           "ldapsearch command failure",
			dn:             "CN=NonExistent,DC=contoso,DC=com",
			fqdn:           "contoso.com",
			mockOutput:     []byte("No such object"),
			mockErr:        errors.New("ldapsearch failed with exit code 1"),
			expectedOutput: nil,
			expectError:    true,
			errorContains:  "failed to execute ldapsearch command",
		},
		{
			name:           "Empty DN",
			dn:             "",
			fqdn:           "contoso.com",
			mockOutput:     nil,
			mockErr:        errors.New("invalid empty DN"),
			expectedOutput: nil,
			expectError:    true,
			errorContains:  "failed to execute ldapsearch command",
		},
		{
			name:           "Empty FQDN",
			dn:             "CN=WebApp01,DC=contoso,DC=com",
			fqdn:           "",
			mockOutput:     nil,
			mockErr:        errors.New("invalid empty FQDN"),
			expectedOutput: nil,
			expectError:    true,
			errorContains:  "failed to execute ldapsearch command",
		},
		{
			name:           "Large response",
			dn:             "CN=WebApp01,DC=contoso,DC=com",
			fqdn:           "contoso.com",
			mockOutput:     []byte(strings.Repeat("A", 4096)), // 4KB response
			mockErr:        nil,
			expectedOutput: []byte(strings.Repeat("A", 4096)),
			expectError:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockExecutor := &MockLdapsearchExecutor{
				Output: tc.mockOutput,
				Err:    tc.mockErr,
			}

			client := NewClient()
			ctx := context.Background()
			output, err := client.SearchGMSAPassword(ctx, tc.dn, tc.fqdn, mockExecutor)

			assert.Equal(t, tc.dn, mockExecutor.CalledWithDN, "Executor should be called with the correct DN")
			assert.Equal(t, tc.fqdn, mockExecutor.CalledWithFQDN, "Executor should be called with the correct FQDN")
			assert.Equal(t, 1, mockExecutor.CalledCount, "Executor should be called exactly once")

			if tc.expectError {
				assert.Error(t, err, "Expected an error but got none")
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains, "Error message should contain expected text")
				}
				assert.Nil(t, output, "Output should be nil when there's an error")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.Equal(t, tc.expectedOutput, output, "Output doesn't match expected value")
				assert.NotNil(t, output, "Output should not be nil for successful calls")
			}
		})
	}
}

func TestExtractManagedPassword(t *testing.T) {
	testCases := []struct {
		name          string
		input         []byte
		expected      []byte
		expectError   bool
		errorContains string
	}{
		{
			name:        "Basic extraction",
			input:       []byte("msDS-ManagedPassword:: ABCDEF123456"),
			expected:    []byte("msDS-ManagedPassword:: ABCDEF123456"),
			expectError: false,
		},
		{
			name:        "Empty input",
			input:       []byte{},
			expected:    []byte{},
			expectError: false,
		},
		{
			name:        "Multiline LDAP response",
			input:       []byte("dn: CN=WebApp01,DC=contoso,DC=com\nmsDS-ManagedPassword:: ABCDEF123456"),
			expected:    []byte("dn: CN=WebApp01,DC=contoso,DC=com\nmsDS-ManagedPassword:: ABCDEF123456"),
			expectError: false,
		},
		{
			name:        "Very large password blob",
			input:       []byte("msDS-ManagedPassword:: " + strings.Repeat("A", 4096)),
			expected:    []byte("msDS-ManagedPassword:: " + strings.Repeat("A", 4096)),
			expectError: false,
		},
		{
			name:        "Binary data",
			input:       []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC},
			expected:    []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := extractManagedPassword(tc.input)

			if tc.expectError {
				assert.Error(t, err, "Expected an error but got none")
				if tc.errorContains != "" {
					assert.Contains(t, err.Error(), tc.errorContains, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.Equal(t, tc.expected, result, "Extracted password doesn't match expected value")
			}
		})
	}

	// This test documents the current implementation and notes that it needs to be updated
	// when proper parsing is implemented
	t.Log("Note: TestExtractManagedPassword passes with the current implementation, but should be updated when proper BLOB parsing is implemented")
}

// Test nil executor handling
func TestSearchGMSAPasswordWithNilExecutor(t *testing.T) {
	client := NewClient()
	ctx := context.Background()

	// This should not panic since we now handle nil executor by creating a default one
	_, err := client.SearchGMSAPassword(ctx, "test-dn", "test-fqdn", nil)

	// We expect an error since the default executor will try to run the actual ldapsearch command
	// which likely won't work in the test environment
	assert.Error(t, err)
}
func TestBuildLdapsearchCommand(t *testing.T) {
	executor := NewDefaultLdapsearchExecutor()

	testCases := []struct {
		name                string
		dn                  string
		fqdn                string
		expectedCmd         string
		expectedArgsContain []string
	}{
		{
			name:        "Basic command building",
			dn:          "CN=WebApp01,DC=contoso,DC=com",
			fqdn:        "contoso.com",
			expectedCmd: "ldapsearch -o ldif_wrap=no -LLL -Y GSSAPI -H ldap://contoso.com",
			expectedArgsContain: []string{
				"-b", "CN=WebApp01,DC=contoso,DC=com",
				"-s", "sub",
				"msDS-ManagedPassword", "-N",
			},
		},
		{
			name:        "Empty DN",
			dn:          "",
			fqdn:        "contoso.com",
			expectedCmd: "ldapsearch -o ldif_wrap=no -LLL -Y GSSAPI -H ldap://contoso.com",
			expectedArgsContain: []string{
				"-b", "",
				"-s", "sub",
				"msDS-ManagedPassword", "-N",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd, args := executor.buildLdapsearchCommand(tc.dn, tc.fqdn)

			assert.Equal(t, tc.expectedCmd, cmd, "Command should match expected value")

			for _, expectedArg := range tc.expectedArgsContain {
				found := false
				for _, arg := range args {
					if arg == expectedArg {
						found = true
						break
					}
				}
				assert.True(t, found, "Expected argument %s not found in args: %v", expectedArg, args)
			}
		})
	}
}
