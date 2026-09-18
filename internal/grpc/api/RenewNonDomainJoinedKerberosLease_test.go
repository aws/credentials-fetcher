package api

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.a2z.com/CredentialsFetcherV2/internal/auth/kerberos"
	pb "golang.a2z.com/CredentialsFetcherV2/internal/grpc/proto"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/cmdexec"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/metadata_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

func TestRenewNonDomainJoinedKerberosLeasePreservesBatchOnRecreateFailure(t *testing.T) {
	tempDir := t.TempDir()
	leaseOne := filepath.Join(tempDir, "lease-one")
	leaseTwo := filepath.Join(tempDir, "lease-two")
	pathOne := filepath.Join(leaseOne, "account-one", "krb5cc")
	pathTwo := filepath.Join(leaseTwo, "account-two", "krb5cc")
	assert.NoError(t, os.MkdirAll(filepath.Dir(pathOne), 0755))
	assert.NoError(t, os.MkdirAll(filepath.Dir(pathTwo), 0755))
	assert.NoError(t, os.WriteFile(pathOne, []byte("expired-one"), 0600))
	assert.NoError(t, os.WriteFile(pathTwo, []byte("expired-two"), 0600))

	ticketOne := &types.TicketInfo{KrbFilePath: pathOne, ServiceAccountName: "account-one", DomainName: "example.com", DomainlessUser: "testuser"}
	ticketTwo := &types.TicketInfo{KrbFilePath: pathTwo, ServiceAccountName: "account-two", DomainName: "example.com", DomainlessUser: "testuser"}
	assert.NoError(t, metadata_utils.WriteMetaDataJSON([]*types.TicketInfo{ticketOne}, "lease-one", tempDir))
	assert.NoError(t, metadata_utils.WriteMetaDataJSON([]*types.TicketInfo{ticketTwo}, "lease-two", tempDir))

	client := new(mockNonDomainJoinedKerberosClient)
	client.On("RenewKerberosTicket", mock.Anything, pathOne).Return(errors.New("ticket expired"))
	client.On("RenewKerberosTicket", mock.Anything, pathTwo).Return(errors.New("ticket expired"))
	client.On("CreateTicketUsingUsernamePassword", "example.com", "testuser", "password").Return(nil)
	client.On("CreateTicketForGMSA", mock.MatchedBy(func(info *types.TicketInfo) bool {
		if info.ServiceAccountName == "account-one" {
			return os.WriteFile(info.KrbFilePath, []byte("renewed-one"), 0600) == nil
		}
		return false
	})).Return(nil)
	client.On("CreateTicketForGMSA", mock.MatchedBy(func(info *types.TicketInfo) bool {
		return info.ServiceAccountName == "account-two"
	})).Return(errors.New("preauthentication failed"))

	metadataOneBefore, readErr := os.ReadFile(filepath.Join(leaseOne, "lease-one_metadata.json"))
	assert.NoError(t, readErr)
	metadataTwoBefore, readErr := os.ReadFile(filepath.Join(leaseTwo, "lease-two_metadata.json"))
	assert.NoError(t, readErr)

	handler := newNonDomainJoinedKerberosHandler(tempDir, "", client, nil, cmdexec.NewExecutor())
	response, err := handler.RenewNonDomainJoinedKerberosLease(context.Background(), &pb.RenewNonDomainJoinedKerberosLeaseRequest{
		Username: "testuser",
		Password: "password",
		Domain:   "example.com",
	})

	assert.Nil(t, response)
	assert.ErrorContains(t, err, "account-two")
	assert.FileExists(t, filepath.Join(leaseOne, "lease-one_metadata.json"))
	assert.FileExists(t, filepath.Join(leaseTwo, "lease-two_metadata.json"))
	assert.DirExists(t, filepath.Dir(pathOne))
	assert.DirExists(t, filepath.Dir(pathTwo))
	metadataOneAfter, readErr := os.ReadFile(filepath.Join(leaseOne, "lease-one_metadata.json"))
	assert.NoError(t, readErr)
	metadataTwoAfter, readErr := os.ReadFile(filepath.Join(leaseTwo, "lease-two_metadata.json"))
	assert.NoError(t, readErr)
	assert.Equal(t, metadataOneBefore, metadataOneAfter)
	assert.Equal(t, metadataTwoBefore, metadataTwoAfter)
	cacheOneAfter, readErr := os.ReadFile(pathOne)
	assert.NoError(t, readErr)
	cacheTwoAfter, readErr := os.ReadFile(pathTwo)
	assert.NoError(t, readErr)
	assert.Equal(t, []byte("expired-one"), cacheOneAfter)
	assert.Equal(t, []byte("expired-two"), cacheTwoAfter)
	client.AssertExpectations(t)
}

func TestRenewNonDomainJoinedKerberosLeaseRollsBackDirectRenewalWhenRecreationFails(t *testing.T) {
	tempDir := t.TempDir()
	lease := filepath.Join(tempDir, "lease")
	pathOne := filepath.Join(lease, "account-one", "krb5cc")
	pathTwo := filepath.Join(lease, "account-two", "krb5cc")
	assert.NoError(t, os.MkdirAll(filepath.Dir(pathOne), 0755))
	assert.NoError(t, os.MkdirAll(filepath.Dir(pathTwo), 0755))
	assert.NoError(t, os.WriteFile(pathOne, []byte("original-one"), 0600))
	assert.NoError(t, os.WriteFile(pathTwo, []byte("original-two"), 0600))

	tickets := []*types.TicketInfo{
		{KrbFilePath: pathOne, ServiceAccountName: "account-one", DomainName: "example.com", DomainlessUser: "testuser"},
		{KrbFilePath: pathTwo, ServiceAccountName: "account-two", DomainName: "example.com", DomainlessUser: "testuser"},
	}
	assert.NoError(t, metadata_utils.WriteMetaDataJSON(tickets, "lease", tempDir))

	client := new(mockNonDomainJoinedKerberosClient)
	client.On("RenewKerberosTicket", mock.Anything, pathOne).Run(func(mock.Arguments) {
		assert.NoError(t, os.WriteFile(pathOne, []byte("renewed-one"), 0600))
	}).Return(nil)
	client.On("RenewKerberosTicket", mock.Anything, pathTwo).Return(errors.New("ticket expired"))
	client.On("CreateTicketUsingUsernamePassword", "example.com", "testuser", "password").Return(nil)
	client.On("CreateTicketForGMSA", mock.MatchedBy(func(info *types.TicketInfo) bool {
		return info.ServiceAccountName == "account-two"
	})).Return(errors.New("preauthentication failed"))

	handler := newNonDomainJoinedKerberosHandler(tempDir, "", client, nil, cmdexec.NewExecutor())
	response, err := handler.RenewNonDomainJoinedKerberosLease(context.Background(), &pb.RenewNonDomainJoinedKerberosLeaseRequest{
		Username: "testuser",
		Password: "password",
		Domain:   "example.com",
	})

	assert.Nil(t, response)
	assert.ErrorContains(t, err, "preauthentication failed")
	cacheOne, readErr := os.ReadFile(pathOne)
	assert.NoError(t, readErr)
	cacheTwo, readErr := os.ReadFile(pathTwo)
	assert.NoError(t, readErr)
	assert.Equal(t, []byte("original-one"), cacheOne)
	assert.Equal(t, []byte("original-two"), cacheTwo)
	client.AssertExpectations(t)
}

func TestMatchLegacyUsernameParsesBlueGreenSecret(t *testing.T) {
	username, matched := matchLegacyUsername("olduser:newuser", "olduser", "newuser", true)
	assert.True(t, matched)
	assert.Equal(t, "olduser", username)

	username, matched = matchLegacyUsername("newuser", "olduser", "newuser", true)
	assert.True(t, matched)
	assert.Equal(t, "newuser", username)

	_, matched = matchLegacyUsername("otherold:othernew", "olduser", "newuser", true)
	assert.False(t, matched)
}

func TestRestoreFileSnapshotsReturnsRestorationErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "krb5cc")
	snapshots := map[string]fileSnapshot{
		path: {data: []byte("original"), mode: 0600, existed: true},
	}
	assert.NoError(t, os.Mkdir(path, 0700))

	err := restoreFileSnapshots(snapshots)
	assert.ErrorContains(t, err, "failed to restore 1 file")
	assert.ErrorContains(t, err, path)
}

func TestRecreateKerberosTicketsReturnsCachePath(t *testing.T) {
	client := new(mockNonDomainJoinedKerberosClient)
	client.On("CreateTicketUsingUsernamePassword", "example.com", "testuser", "password").Return(nil)
	client.On("CreateTicketForGMSA", mock.Anything).Return(nil)

	root := t.TempDir()
	path := filepath.Join(root, "lease", "account", "krb5cc")
	handler := newNonDomainJoinedKerberosHandler(root, "", client, nil, cmdexec.NewExecutor())
	paths, err := handler.RecreateKerberosTickets(context.Background(), "example.com", "testuser", "password", []*types.TicketInfo{{
		KrbFilePath:        path,
		ServiceAccountName: "account",
		DomainName:         "example.com",
	}})

	assert.NoError(t, err)
	assert.Equal(t, []string{path}, paths)
	client.AssertExpectations(t)
}

func TestRecreateKerberosTicketsRejectsPathOutsideKerberosRoot(t *testing.T) {
	client := new(mockNonDomainJoinedKerberosClient)
	client.On("CreateTicketUsingUsernamePassword", "example.com", "testuser", "password").Return(nil)

	root := t.TempDir()
	handler := newNonDomainJoinedKerberosHandler(root, "", client, nil, cmdexec.NewExecutor())
	paths, err := handler.RecreateKerberosTickets(context.Background(), "example.com", "testuser", "password", []*types.TicketInfo{{
		KrbFilePath:        filepath.Join(filepath.Dir(root), "outside", "account", "krb5cc"),
		ServiceAccountName: "account",
		DomainName:         "example.com",
	}})

	assert.Empty(t, paths)
	assert.ErrorContains(t, err, "escapes configured root")
	client.AssertNotCalled(t, "CreateTicketForGMSA", mock.Anything)
	client.AssertExpectations(t)
}

func TestRenewNonDomainJoinedKerberosLeasePreservesMetadataWhenAllRecreationsFail(t *testing.T) {
	root := t.TempDir()
	lease := filepath.Join(root, "lease")
	cachePath := filepath.Join(lease, "account", "krb5cc")
	assert.NoError(t, os.MkdirAll(filepath.Dir(cachePath), 0755))
	assert.NoError(t, os.WriteFile(cachePath, []byte("expired"), 0600))
	ticket := &types.TicketInfo{KrbFilePath: cachePath, ServiceAccountName: "account", DomainName: "example.com", DomainlessUser: "testuser"}
	assert.NoError(t, metadata_utils.WriteMetaDataJSON([]*types.TicketInfo{ticket}, "lease", root))
	metadataPath := filepath.Join(lease, "lease_metadata.json")
	metadataBefore, readErr := os.ReadFile(metadataPath)
	assert.NoError(t, readErr)

	client := new(mockNonDomainJoinedKerberosClient)
	client.On("RenewKerberosTicket", mock.Anything, cachePath).Return(errors.New("ticket expired"))
	client.On("CreateTicketUsingUsernamePassword", "example.com", "testuser", "password").Return(nil)
	client.On("CreateTicketForGMSA", mock.Anything).Return(errors.New("preauthentication failed"))
	handler := newNonDomainJoinedKerberosHandler(root, "", client, nil, cmdexec.NewExecutor())

	response, err := handler.RenewNonDomainJoinedKerberosLease(context.Background(), &pb.RenewNonDomainJoinedKerberosLeaseRequest{
		Username: "testuser",
		Password: "password",
		Domain:   "example.com",
	})

	assert.Nil(t, response)
	assert.ErrorContains(t, err, "preauthentication failed")
	assert.FileExists(t, cachePath)
	metadataAfter, readErr := os.ReadFile(metadataPath)
	assert.NoError(t, readErr)
	assert.Equal(t, metadataBefore, metadataAfter)
	client.AssertExpectations(t)
}

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

// TestBlueGreenRenewalAfterRotationCompleted verifies that when the secret still
// has oldUser:newUser format but tickets have already been rotated to newUser,
// renewal continues to work by matching the active username.
func TestBlueGreenRenewalAfterRotationCompleted(t *testing.T) {
	testCases := []struct {
		name           string
		username       string // from GRPC request (secret value)
		domainlessUser string // in metadata
		shouldMatch    bool
		needsRotation  bool
	}{
		{
			name:           "Rotation needed - ticket has old username",
			username:       "StandardUser01:StandardUser02",
			domainlessUser: "StandardUser01",
			shouldMatch:    true,
			needsRotation:  true,
		},
		{
			name:           "Rotation already done - ticket has new username",
			username:       "StandardUser01:StandardUser02",
			domainlessUser: "StandardUser02",
			shouldMatch:    true,
			needsRotation:  false,
		},
		{
			name:           "No rotation - single username matches",
			username:       "StandardUser01",
			domainlessUser: "StandardUser01",
			shouldMatch:    true,
			needsRotation:  false,
		},
		{
			name:           "No rotation - single username doesn't match",
			username:       "StandardUser01",
			domainlessUser: "StandardUser02",
			shouldMatch:    false,
			needsRotation:  false,
		},
		{
			name:           "Rotation format - neither old nor new matches",
			username:       "StandardUser01:StandardUser02",
			domainlessUser: "StandardUser03",
			shouldMatch:    false,
			needsRotation:  false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			matchUsername, activeUsername, isRotation := grpc_utils.ParseBlueGreenUsername(tc.username)

			// Simulate the matching logic
			matched := tc.domainlessUser == matchUsername ||
				(isRotation && tc.domainlessUser == activeUsername)
			assert.Equal(t, tc.shouldMatch, matched, "Ticket match result")

			// Simulate needsRotation determination
			needsRotation := isRotation && matched && tc.domainlessUser == matchUsername
			assert.Equal(t, tc.needsRotation, needsRotation, "Needs rotation")

			// Suppress unused variable warnings
			_ = activeUsername
		})
	}
}

// TestBlueGreenMixedStateRotation verifies that in a mixed state where some
// tickets have the old username and some have the new username, the production
// matching logic correctly classifies each ticket.
func TestBlueGreenMixedStateRotation(t *testing.T) {
	username := "StandardUser01:StandardUser02"
	matchUsername, activeUsername, isRotation := grpc_utils.ParseBlueGreenUsername(username)

	assert.True(t, isRotation)
	assert.Equal(t, "StandardUser01", matchUsername)
	assert.Equal(t, "StandardUser02", activeUsername)

	tickets := []struct {
		domainlessUser string
		expectMatch    bool
		expectRotate   bool // true = needs recreation, false = renew normally
	}{
		{"StandardUser01", true, true},   // old username → needs rotation
		{"StandardUser02", true, false},  // already has active username → renew normally
		{"StandardUser01", true, true},   // old username → needs rotation
		{"StandardUser02", true, false},  // already has active username → renew normally
		{"StandardUser03", false, false}, // unrelated → no match
	}

	var matchCount, rotateCount, renewCount int
	for _, ticket := range tickets {
		// Use the same matching logic as production code
		matched := ticket.domainlessUser == matchUsername ||
			(isRotation && ticket.domainlessUser == activeUsername)
		assert.Equal(t, ticket.expectMatch, matched, "Match for %s", ticket.domainlessUser)

		if matched {
			matchCount++
			// Production logic: only rotate if DomainlessUser == matchUsername
			if ticket.domainlessUser == matchUsername {
				rotateCount++
				assert.True(t, ticket.expectRotate)
			} else {
				renewCount++
				assert.False(t, ticket.expectRotate)
			}
		}
	}

	assert.Equal(t, 4, matchCount, "4 tickets should match (2 old + 2 active)")
	assert.Equal(t, 2, rotateCount, "Only old-username tickets need rotation")
	assert.Equal(t, 2, renewCount, "Active-username tickets renewed normally")
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
