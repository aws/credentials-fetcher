package aws_utils

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

// Mock Secrets Manager client
type mockSecretsManagerClient struct {
	secretsmanageriface.SecretsManagerAPI
	getSecretValueOutput secretsmanager.GetSecretValueOutput
	getSecretValueError  error
}

func (m *mockSecretsManagerClient) GetSecretValue(input *secretsmanager.GetSecretValueInput) (*secretsmanager.GetSecretValueOutput, error) {
	return &m.getSecretValueOutput, m.getSecretValueError
}

func TestGetSecretSuccess(t *testing.T) {
	// Mock data
	secretData := map[string]string{
		"username": "testuser",
		"password": "testpassword",
	}
	secretJSON, _ := json.Marshal(secretData)

	// Mock client with successful response
	client := &mockSecretsManagerClient{
		getSecretValueOutput: secretsmanager.GetSecretValueOutput{
			SecretString: aws.String(string(secretJSON)),
		},
	}

	// Call function with mocked client
	result, err := getSecretWithClient(client, "test-secret-arn")

	// Verify results
	if err != nil {
		t.Errorf("Expected no error, got: %v", err)
	}

	// Check if username matches
	username, ok := result["username"].(string)
	if !ok || username != "testuser" {
		t.Errorf("Expected username 'testuser', got %v", result["username"])
	}
}

func TestGetSecretAPIError(t *testing.T) {
	// Mock client with error response
	client := &mockSecretsManagerClient{
		getSecretValueError: errors.New("access denied"),
	}

	// Call function with mocked client
	_, err := getSecretWithClient(client, "test-secret-arn")

	// Verify error
	if err == nil {
		t.Error("Expected an error, got nil")
	}
	if err.Error() != "failed to get secret value: access denied" {
		t.Errorf("Unexpected error message: %v", err)
	}
}

func TestGetSecretInvalidJSON(t *testing.T) {
	// Mock client with invalid JSON response
	client := &mockSecretsManagerClient{
		getSecretValueOutput: secretsmanager.GetSecretValueOutput{
			SecretString: aws.String("invalid json"),
		},
	}

	// Call function with mocked client
	_, err := getSecretWithClient(client, "test-secret-arn")

	// Verify error
	if err == nil {
		t.Error("Expected an error, got nil")
	}
	if err.Error()[:22] != "failed to parse secret" {
		t.Errorf("Unexpected error message: %v", err)
	}
}
