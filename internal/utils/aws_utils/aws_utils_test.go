package aws_utils

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/stretchr/testify/assert"
)

// Mock Secrets Manager client
type mockSecretsManagerClient struct {
	getSecretValueOutput *secretsmanager.GetSecretValueOutput
	getSecretValueError  error
}

func (m *mockSecretsManagerClient) GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error) {
	return m.getSecretValueOutput, m.getSecretValueError
}

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

func TestGetSecretWithClient(t *testing.T) {
	tests := []struct {
		name          string
		secretArn     string
		secretString  string
		mockError     error
		expectedMap   map[string]interface{}
		expectedError bool
	}{
		{
			name:         "Valid secret",
			secretArn:    "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret",
			secretString: `{"username":"testuser","password":"testpass"}`,
			mockError:    nil,
			expectedMap: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
			expectedError: false,
		},
		{
			name:          "API error",
			secretArn:     "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret",
			secretString:  "",
			mockError:     errors.New("API error"),
			expectedMap:   nil,
			expectedError: true,
		},
		{
			name:          "Invalid JSON",
			secretArn:     "arn:aws:secretsmanager:us-west-2:123456789012:secret:test-secret",
			secretString:  `{"username":"testuser","password":}`, // Invalid JSON
			mockError:     nil,
			expectedMap:   nil,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock client
			mockClient := &mockSecretsManagerClient{
				getSecretValueError: tt.mockError,
			}

			if tt.mockError == nil {
				mockClient.getSecretValueOutput = &secretsmanager.GetSecretValueOutput{
					SecretString: aws.String(tt.secretString),
				}
			}

			// Call the function
			result, err := getSecretWithClient(context.Background(), mockClient, tt.secretArn)

			// Check results
			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedMap, result)
			}
		})
	}
}
