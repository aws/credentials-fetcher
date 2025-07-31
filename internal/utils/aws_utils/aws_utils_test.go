package aws_utils

import (
	"os/exec"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractCredentialsFromSecret(t *testing.T) {
	tests := []struct {
		name           string
		secretMap      map[string]interface{}
		wantUsername   string
		wantPassword   string
		wantDN         string
		wantErr        bool
		expectedErrMsg string
	}{
		{
			name: "Valid secret with primary fields",
			secretMap: map[string]interface{}{
				"username":          "testuser",
				"password":          "testpass",
				"distinguishedName": "CN=Test,DC=example,DC=com",
			},
			wantUsername: "testuser",
			wantPassword: "testpass",
			wantDN:       "CN=Test,DC=example,DC=com",
			wantErr:      false,
		},
		{
			name: "Valid secret with alternate fields",
			secretMap: map[string]interface{}{
				"usernameOfStandardUserAccount": "altuser",
				"passwordOfStandardUserAccount": "altpass",
				"distinguishedNameOfgMSA":       "CN=AltTest,DC=example,DC=com",
			},
			wantUsername: "altuser",
			wantPassword: "altpass",
			wantDN:       "CN=AltTest,DC=example,DC=com",
			wantErr:      false,
		},
		{
			name: "Valid secret with mixed fields",
			secretMap: map[string]interface{}{
				"username":                      "testuser",
				"passwordOfStandardUserAccount": "altpass",
				"distinguishedNameOfgMSA":       "CN=MixTest,DC=example,DC=com",
			},
			wantUsername: "testuser",
			wantPassword: "altpass",
			wantDN:       "CN=MixTest,DC=example,DC=com",
			wantErr:      false,
		},
		{
			name: "Valid secret without DN",
			secretMap: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
			wantUsername: "testuser",
			wantPassword: "testpass",
			wantDN:       "",
			wantErr:      false,
		},
		{
			name:           "Nil secret map",
			secretMap:      nil,
			wantUsername:   "",
			wantPassword:   "",
			wantDN:         "",
			wantErr:        true,
			expectedErrMsg: "secret map is nil",
		},
		{
			name: "Missing username",
			secretMap: map[string]interface{}{
				"password": "testpass",
			},
			wantUsername:   "",
			wantPassword:   "",
			wantDN:         "",
			wantErr:        true,
			expectedErrMsg: "username not found in secret",
		},
		{
			name: "Missing password",
			secretMap: map[string]interface{}{
				"username": "testuser",
			},
			wantUsername:   "",
			wantPassword:   "",
			wantDN:         "",
			wantErr:        true,
			expectedErrMsg: "password not found in secret",
		},
		{
			name: "Empty username",
			secretMap: map[string]interface{}{
				"username": "",
				"password": "testpass",
			},
			wantUsername:   "",
			wantPassword:   "",
			wantDN:         "",
			wantErr:        true,
			expectedErrMsg: "username not found in secret",
		},
		{
			name: "Empty password",
			secretMap: map[string]interface{}{
				"username": "testuser",
				"password": "",
			},
			wantUsername:   "",
			wantPassword:   "",
			wantDN:         "",
			wantErr:        true,
			expectedErrMsg: "password not found in secret",
		},
		{
			name: "Non-string username",
			secretMap: map[string]interface{}{
				"username": 123,
				"password": "testpass",
			},
			wantUsername:   "",
			wantPassword:   "",
			wantDN:         "",
			wantErr:        true,
			expectedErrMsg: "username not found in secret",
		},
		{
			name: "Non-string password",
			secretMap: map[string]interface{}{
				"username": "testuser",
				"password": 123,
			},
			wantUsername:   "",
			wantPassword:   "",
			wantDN:         "",
			wantErr:        true,
			expectedErrMsg: "password not found in secret",
		},
		{
			name: "Non-string DN",
			secretMap: map[string]interface{}{
				"username":          "testuser",
				"password":          "testpass",
				"distinguishedName": 123,
			},
			wantUsername: "testuser",
			wantPassword: "testpass",
			wantDN:       "",
			wantErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			username, password, domain, dn, err := ExtractCredentialsFromSecret(tt.secretMap)
			_ = domain // Ignore domain for this test

			if tt.wantErr {
				assert.Error(t, err)
				if tt.expectedErrMsg != "" {
					assert.Contains(t, err.Error(), tt.expectedErrMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantUsername, username)
				assert.Equal(t, tt.wantPassword, password)
				assert.Equal(t, tt.wantDN, dn)
			}
		})
	}
}

// Mock command executor for testing
type mockCommandExecutor struct {
	output []byte
	err    error
}

func (m *mockCommandExecutor) Output() ([]byte, error) {
	return m.output, m.err
}

func TestExecuteSecretsManagerCLI(t *testing.T) {
	tests := []struct {
		name          string
		cliOutput     string
		expectedMap   map[string]interface{}
		expectedError bool
	}{
		{
			name:      "Valid CLI response",
			cliOutput: `{"SecretString":"{\"username\":\"testuser\",\"password\":\"testpass\"}"}`,
			expectedMap: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
			expectedError: false,
		},
		{
			name:          "Invalid JSON in CLI response",
			cliOutput:     `{"SecretString":"invalid json"}`,
			expectedMap:   nil,
			expectedError: true,
		},
		{
			name:          "Invalid CLI response format",
			cliOutput:     `invalid response`,
			expectedMap:   nil,
			expectedError: true,
		},
	}

	// Save original function
	originalNewCommandExecutor := newCommandExecutor
	defer func() {
		newCommandExecutor = originalNewCommandExecutor
	}()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Mock the command executor
			newCommandExecutor = func(cmd *exec.Cmd) CommandExecutor {
				return &mockCommandExecutor{
					output: []byte(tt.cliOutput),
					err:    nil,
				}
			}

			cmd := exec.Command("aws", "secretsmanager", "get-secret-value")
			result, err := executeSecretsManagerCLI(cmd)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, result)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedMap, result)
			}
		})
	}
}

func TestGetSecretFromSecretsManager(t *testing.T) {
	// Save original function
	originalNewCommandExecutor := newCommandExecutor
	defer func() {
		newCommandExecutor = originalNewCommandExecutor
	}()

	// Mock successful response
	newCommandExecutor = func(cmd *exec.Cmd) CommandExecutor {
		return &mockCommandExecutor{
			output: []byte(`{"SecretString":"{\"username\":\"testuser\",\"password\":\"testpass\"}"}`),
			err:    nil,
		}
	}

	result, err := GetSecretFromSecretsManager("test-arn")

	assert.NoError(t, err)
	expected := map[string]interface{}{
		"username": "testuser",
		"password": "testpass",
	}
	assert.Equal(t, expected, result)
}
