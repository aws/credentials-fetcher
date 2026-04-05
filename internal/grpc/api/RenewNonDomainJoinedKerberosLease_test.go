package api

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"golang.a2z.com/CredentialsFetcherV2/internal/auth/kerberos"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"
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

// TestBlueGreenUsernameParsingInRenewFlow tests that the blue/green username
// rotation format ("oldUser:newUser") used during Secrets Manager credential
// rotation is properly parsed and validated in the renew flow.
func TestBlueGreenUsernameParsingInRenewFlow(t *testing.T) {
	handler := &NonDomainJoinedKerberosHandler{
		krbFilesDir:     "/tmp/krb",
		awsSMSecretName: "test-secret",
		krbClient:       kerberos.NewClient(),
		shellExecutor:   cmdexec.NewExecutor(),
	}

	t.Run("Blue/green format - both usernames valid", func(t *testing.T) {
		matchUser, activeUser, isRotation := grpc_utils.ParseBlueGreenUsername("olduser:newuser")
		assert.True(t, isRotation)
		assert.Equal(t, "olduser", matchUser)
		assert.Equal(t, "newuser", activeUser)

		// Both parts should pass individual validation
		assert.NoError(t, handler.ValidateCredentials(activeUser, "password", "example.com"))
		assert.NoError(t, grpc_utils.ValidateAccountName(matchUser))
	})

	t.Run("Blue/green format - new username invalid", func(t *testing.T) {
		_, activeUser, isRotation := grpc_utils.ParseBlueGreenUsername("olduser:invalid user")
		assert.True(t, isRotation)

		// Active (new) username has a space → should fail validation
		err := handler.ValidateCredentials(activeUser, "password", "example.com")
		assert.Error(t, err)
	})

	t.Run("Blue/green format - old username invalid", func(t *testing.T) {
		matchUser, _, isRotation := grpc_utils.ParseBlueGreenUsername("old user:newuser")
		assert.True(t, isRotation)

		// Old username has a space → should fail validation
		err := grpc_utils.ValidateAccountName(matchUser)
		assert.Error(t, err)
	})

	t.Run("Normal username (no colon) - passes validation", func(t *testing.T) {
		matchUser, activeUser, isRotation := grpc_utils.ParseBlueGreenUsername("singleuser")
		assert.False(t, isRotation)
		assert.Equal(t, "singleuser", matchUser)
		assert.Equal(t, "singleuser", activeUser)

		assert.NoError(t, handler.ValidateCredentials(activeUser, "password", "example.com"))
	})
}
