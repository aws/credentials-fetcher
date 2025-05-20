package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.a2z.com/CredentialsFetcherV2/internal/auth/kerberos"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
)

// TestRenewNonDomainJoinedKerberosLease_ValidateCredentials tests the validation of credentials
func TestRenewNonDomainJoinedKerberosLease_ValidateCredentials(t *testing.T) {
	// Create test cases
	testCases := []struct {
		name          string
		username      string
		password      string
		domain        string
		expectedError bool
	}{
		{
			name:          "Valid credentials",
			username:      "testuser",
			password:      "testpassword",
			domain:        "example.com",
			expectedError: false,
		},
		{
			name:          "Empty username",
			username:      "",
			password:      "testpassword",
			domain:        "example.com",
			expectedError: true,
		},
		{
			name:          "Empty password",
			username:      "testuser",
			password:      "",
			domain:        "example.com",
			expectedError: true,
		},
		{
			name:          "Empty domain",
			username:      "testuser",
			password:      "testpassword",
			domain:        "",
			expectedError: true,
		},
	}

	// Create a handler
	handler := &NonDomainJoinedKerberosHandler{
		krbFilesDir:     "/tmp/krb",
		awsSMSecretName: "test-secret",
		krbClient:       kerberos.NewClient(),
		shellExecutor:   cmdexec.NewExecutor(),
	}

	// Run test cases
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the ValidateCredentials function directly
			err := handler.ValidateCredentials(tc.username, tc.password, tc.domain)

			// Verify results
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
