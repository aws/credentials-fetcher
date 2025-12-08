package krb_utils

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
)

// Mock implementation of Krb5Client for testing
type krb5ClientMock struct {
	mock.Mock
}

func (m *krb5ClientMock) GenerateTicket(config *KinitConfig) error {
	args := m.Called(config)
	return args.Error(0)
}

func (m *krb5ClientMock) VerifyTicket(ccachePath string) error {
	args := m.Called(ccachePath)
	return args.Error(0)
}

func TestGenerateKerberosTicket(t *testing.T) {
	// Get username from environment
	username := os.Getenv("KRB5_TEST_USERNAME")
	if username == "" {
		t.Skip("KRB5_TEST_USERNAME environment variable not set. To run this test, set your username: export KRB5_TEST_USERNAME='your-username'")
	}

	// Get password from environment variable
	password := os.Getenv("KRB5_TEST_PASSWORD")
	if password == "" {
		t.Skip("KRB5_TEST_PASSWORD environment variable not set. To run this test, set your password: export KRB5_TEST_PASSWORD='your-password'")
	}

	// Get domain from environment variable
	domain := os.Getenv("KRB5_TEST_DOMAIN")
	if domain == "" {
		t.Skip("KRB5_TEST_DOMAIN environment variable not set. To run this test, set your domain: export KRB5_TEST_DOMAIN='EXAMPLE.COM'")
	}

	// Configuration for testing
	principal := username + "@" + domain

	// Get cache path from environment variable, or use default
	cachePath := os.Getenv("KRB5_TEST_CACHE_PATH")
	if cachePath == "" {
		// Default: use /tmp/krb5cc_test_<username>
		cachePath = "/tmp/krb5cc_test_" + username
	}
	t.Logf("Using cache path: %s", cachePath)

	t.Logf("Testing kinit for principal: %s", principal)

	// Clean up any existing test cache
	defer func() { _ = os.Remove(cachePath) }()

	config := NewKinitConfigWithCache(principal, password, cachePath)
	config.Verbose = true

	err := GenerateKerberosTicket(config)
	if err != nil {
		t.Fatalf("Failed to generate Kerberos ticket: %v", err)
	}

	// Verify the cache file was created
	if _, err := os.Stat(cachePath); os.IsNotExist(err) {
		t.Errorf("Cache file was not created at %s", cachePath)
	}

	// Run klist to verify the ticket
	executor := cmdexec.NewExecutor()
	ctx := context.Background()

	// Set KRB5CCNAME environment variable to point to the test cache
	env := []string{"KRB5CCNAME=" + cachePath}

	output, err := executor.ExecuteWithEnv(ctx, "klist", env)
	if err != nil {
		t.Fatalf("Failed to run klist: %v", err)
	}

	outputStr := string(output)
	t.Logf("klist output:\n%s", outputStr)

	// Verify the output contains the principal
	if !strings.Contains(outputStr, principal) {
		t.Errorf("klist output does not contain principal %s", principal)
	}

	// Verify the output contains the ticket cache location
	if !strings.Contains(outputStr, cachePath) {
		t.Errorf("klist output does not contain cache path %s", cachePath)
	}

	// Verify the output contains "krbtgt" (Kerberos Ticket Granting Ticket)
	if !strings.Contains(outputStr, "krbtgt") {
		t.Errorf("klist output does not contain krbtgt ticket")
	}

	// Run klist -s to check ticket validity (silent check)
	// klist -s returns 0 if credentials are valid, 1 if not
	_, err = executor.ExecuteWithEnv(ctx, "klist", env, "-s")
	if err != nil {
		t.Errorf("klist -s validation failed: ticket is invalid or expired: %v", err)
	} else {
		t.Log("Ticket validity check passed (klist -s returned 0)")
	}

	// Run klist -f to show ticket flags for detailed validation
	flagsOutput, err := executor.ExecuteWithEnv(ctx, "klist", env, "-f")
	if err == nil {
		t.Logf("klist -f output (with flags):\n%s", string(flagsOutput))
	} else {
		t.Logf("klist -f failed (might not be supported): %v", err)
	}

	t.Log("Successfully generated and verified Kerberos ticket")
}

func TestNewKinitConfig(t *testing.T) {
	config := NewKinitConfig("test@REALM.COM", "password")

	if config.Principal != "test@REALM.COM" {
		t.Errorf("Expected principal 'test@REALM.COM', got '%s'", config.Principal)
	}

	if config.Password != "password" {
		t.Errorf("Expected password 'password', got '%s'", config.Password)
	}

	if !config.Forwardable {
		t.Error("Expected Forwardable to be true by default")
	}

	if !config.Verify {
		t.Error("Expected Verify to be true by default")
	}
}

func TestNewKinitConfigWithCache(t *testing.T) {
	cachePath := "/tmp/test_cache"
	config := NewKinitConfigWithCache("test@REALM.COM", "password", cachePath)

	if config.CCachePath != cachePath {
		t.Errorf("Expected cache path '%s', got '%s'", cachePath, config.CCachePath)
	}
}

func TestGenerateKerberosTicketValidation(t *testing.T) {
	tests := []struct {
		name      string
		config    *KinitConfig
		wantError bool
	}{
		{
			name: "missing principal",
			config: &KinitConfig{
				Password: "password",
			},
			wantError: true,
		},
		{
			name: "missing password",
			config: &KinitConfig{
				Principal: "test@REALM.COM",
			},
			wantError: true,
		},
		{
			name: "invalid principal",
			config: &KinitConfig{
				Principal: "invalid-principal",
				Password:  "password",
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := GenerateKerberosTicket(tt.config)
			if (err != nil) != tt.wantError {
				t.Errorf("GenerateKerberosTicket() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestGenerateKerberosTicketRenewal(t *testing.T) {
	tests := []struct {
		name          string
		config        *KinitConfig
		mockSetup     func(*krb5ClientMock)
		expectError   bool
		errorContains string
	}{
		{
			name: "successful renewal",
			config: &KinitConfig{
				CCachePath:  "/tmp/krb5cc_test",
				RenewTicket: true,
				Verify:      true,
			},
			mockSetup: func(m *krb5ClientMock) {
				m.On("GenerateTicket", mock.MatchedBy(func(cfg *KinitConfig) bool {
					return cfg.RenewTicket && cfg.CCachePath == "/tmp/krb5cc_test"
				})).Return(nil)
			},
			expectError: false,
		},
		{
			name: "renewal without verify",
			config: &KinitConfig{
				CCachePath:  "/tmp/krb5cc_test",
				RenewTicket: true,
				Verify:      false,
			},
			mockSetup: func(m *krb5ClientMock) {
				m.On("GenerateTicket", mock.MatchedBy(func(cfg *KinitConfig) bool {
					return cfg.RenewTicket && !cfg.Verify
				})).Return(nil)
			},
			expectError: false,
		},
		{
			name: "renewal fails with expired ticket",
			config: &KinitConfig{
				CCachePath:  "/tmp/krb5cc_test",
				RenewTicket: true,
			},
			mockSetup: func(m *krb5ClientMock) {
				m.On("GenerateTicket", mock.Anything).Return(
					fmt.Errorf("failed to renew ticket: KRB5KRB_AP_ERR_TKT_EXPIRED"),
				)
			},
			expectError:   true,
			errorContains: "failed to renew ticket",
		},
		{
			name: "renewal fails with missing cache",
			config: &KinitConfig{
				CCachePath:  "/nonexistent/krb5cc_test",
				RenewTicket: true,
			},
			mockSetup: func(m *krb5ClientMock) {
				m.On("GenerateTicket", mock.Anything).Return(
					fmt.Errorf("failed to resolve cache: No such file or directory"),
				)
			},
			expectError:   true,
			errorContains: "failed to resolve cache",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := new(krb5ClientMock)
			tt.mockSetup(mockClient)

			err := GenerateKerberosTicketWithClient(tt.config, mockClient)

			if tt.expectError {
				assert.Error(t, err)
				if tt.errorContains != "" {
					assert.Contains(t, err.Error(), tt.errorContains)
				}
			} else {
				assert.NoError(t, err)
			}

			mockClient.AssertExpectations(t)
		})
	}
}

// TestGenerateKerberosTicket_NilClient tests that GenerateKerberosTicket handles nil DefaultKrb5Client gracefully
func TestGenerateKerberosTicket_NilClient(t *testing.T) {
	// Save original client
	originalClient := DefaultKrb5Client
	defer func() {
		// Restore original client after test
		DefaultKrb5Client = originalClient
	}()

	// Set DefaultKrb5Client to nil
	DefaultKrb5Client = nil

	config := &KinitConfig{
		Principal:  "test@EXAMPLE.COM",
		Password:   "password",
		CCachePath: "/tmp/krb5cc_test",
	}

	err := GenerateKerberosTicket(config)

	// Should return error when DefaultKrb5Client is nil
	if err == nil {
		t.Error("Expected error when DefaultKrb5Client is nil, got nil")
	}

	expectedError := "DefaultKrb5Client is not initialized"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}

// TestVerifyTicket_NilClient tests that VerifyTicket handles nil DefaultKrb5Client gracefully
func TestVerifyTicket_NilClient(t *testing.T) {
	// Save original client
	originalClient := DefaultKrb5Client
	defer func() {
		// Restore original client after test
		DefaultKrb5Client = originalClient
	}()

	// Set DefaultKrb5Client to nil
	DefaultKrb5Client = nil

	ccachePath := "/tmp/krb5cc_test"

	err := VerifyTicket(ccachePath)

	// Should return error when DefaultKrb5Client is nil
	if err == nil {
		t.Error("Expected error when DefaultKrb5Client is nil, got nil")
	}

	expectedError := "DefaultKrb5Client is not initialized"
	if err != nil && err.Error() != expectedError {
		t.Errorf("Expected error '%s', got '%s'", expectedError, err.Error())
	}
}
