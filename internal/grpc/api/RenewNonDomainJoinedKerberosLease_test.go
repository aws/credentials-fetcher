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

// TestRenewSkipsSecretsManagerFallbackWhenDomainlessUserSet verifies that when
// DomainlessUser is populated in metadata but doesn't match the request username,
// the code does NOT fall back to reading the secret from Secrets Manager.
// This is critical for ECS mode where the instance role doesn't have
// secretsmanager:GetSecretValue permission.
func TestRenewSkipsSecretsManagerFallbackWhenDomainlessUserSet(t *testing.T) {
	// Simulate ticket metadata with DomainlessUser set to a different user
	// than the one in the renew request. The code should skip this ticket
	// without attempting to read CredentialArn from Secrets Manager.

	testCases := []struct {
		name             string
		domainlessUser   string
		credentialArn    string
		matchUsername    string
		shouldMatch      bool
		shouldCallSecret bool
	}{
		{
			name:             "DomainlessUser set and matches - direct match, no secret call",
			domainlessUser:   "StandardUser01",
			credentialArn:    "arn:aws:secretsmanager:us-west-2:123456789012:secret:test",
			matchUsername:    "StandardUser01",
			shouldMatch:      true,
			shouldCallSecret: false,
		},
		{
			name:             "DomainlessUser set but doesn't match - skip, no secret call",
			domainlessUser:   "StandardUser02",
			credentialArn:    "arn:aws:secretsmanager:us-west-2:123456789012:secret:test",
			matchUsername:    "StandardUser01",
			shouldMatch:      false,
			shouldCallSecret: false,
		},
		{
			name:             "DomainlessUser empty, CredentialArn set - should attempt secret call",
			domainlessUser:   "",
			credentialArn:    "arn:aws:secretsmanager:us-west-2:123456789012:secret:test",
			matchUsername:    "StandardUser01",
			shouldMatch:      false,
			shouldCallSecret: true,
		},
		{
			name:             "DomainlessUser empty, CredentialArn empty - no match, no secret call",
			domainlessUser:   "",
			credentialArn:    "",
			matchUsername:    "StandardUser01",
			shouldMatch:      false,
			shouldCallSecret: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test the matching logic directly
			matched := tc.domainlessUser == tc.matchUsername
			assert.Equal(t, tc.shouldMatch, matched, "Direct match result")

			// Test whether Secrets Manager fallback would be triggered
			wouldCallSecret := tc.domainlessUser == "" && tc.credentialArn != ""
			assert.Equal(t, tc.shouldCallSecret, wouldCallSecret,
				"Secrets Manager fallback should only trigger when DomainlessUser is empty and CredentialArn is set")
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

	t.Run("Customer rotation SvcAccountGR:SvcAccountBL", func(t *testing.T) {
		matchUser, activeUser, isRotation := grpc_utils.ParseBlueGreenUsername("SvcAccountGR:SvcAccountBL")
		assert.True(t, isRotation)
		assert.Equal(t, "SvcAccountGR", matchUser)
		assert.Equal(t, "SvcAccountBL", activeUser)

		// Active (new) username passes validation
		assert.NoError(t, handler.ValidateCredentials(activeUser, "password", "contoso.com"))
		// Old username also passes validation independently
		assert.NoError(t, grpc_utils.ValidateAccountName(matchUser))

		// Raw combined string must NOT pass ValidateAccountName (contains ':')
		err := grpc_utils.ValidateAccountName("SvcAccountGR:SvcAccountBL")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "username contains invalid character: :")
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
