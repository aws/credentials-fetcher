package aws_utils

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

var log = logger.GetInstance()

// executeSecretsManagerCLI executes AWS CLI command and parses the response
func executeSecretsManagerCLI(cmd *exec.Cmd) (map[string]interface{}, error) {
	log.Debug("Executing AWS Secrets Manager CLI command", "command", cmd.String())

	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to get secret value using AWS CLI: %v", err)
	}
	log.Debug("AWS Secrets Manager CLI Command completed successfully", "output_size", len(output))

	// Parse AWS CLI output
	var cliResponse struct {
		SecretString string `json:"SecretString"`
	}
	if err := json.Unmarshal(output, &cliResponse); err != nil {
		return nil, fmt.Errorf("failed to parse AWS CLI response: %v", err)
	}

	// Parse the secret string into a map
	var secretMap map[string]interface{}
	if err := json.Unmarshal([]byte(cliResponse.SecretString), &secretMap); err != nil {
		return nil, fmt.Errorf("failed to parse secret JSON: %v", err)
	}

	return secretMap, nil
}

// GetSecretFromSecretsManagerWithConfig retrieves a secret value from AWS Secrets Manager
// using AWS CLI with credentials extracted from AWS config. It returns the secret value as a JSON object (map[string]interface{}).
func GetSecretFromSecretsManagerWithConfig(ctx context.Context, cfg aws.Config, secretArn string) (map[string]interface{}, error) {
	// Extract credentials from AWS config
	creds, err := cfg.Credentials.Retrieve(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credentials from config: %v", err)
	}

	return GetSecretFromSecretsManagerWithCredentials(ctx, secretArn, creds.AccessKeyID, creds.SecretAccessKey, creds.SessionToken, cfg.Region)
}

// GetSecretFromSecretsManagerWithCredentials retrieves a secret value from AWS Secrets Manager
// using AWS CLI with provided credentials. It returns the secret value as a JSON object (map[string]interface{}).
func GetSecretFromSecretsManagerWithCredentials(ctx context.Context, secretArn, accessKeyId, secretAccessKey, sessionToken, region string) (map[string]interface{}, error) {
	// Use AWS CLI to get secret
	cmd := exec.CommandContext(ctx, "aws", "secretsmanager", "get-secret-value", "--secret-id", secretArn, "--output", "json")

	// Set AWS credentials as environment variables
	cmd.Env = append(os.Environ(),
		"AWS_ACCESS_KEY_ID="+accessKeyId,
		"AWS_SECRET_ACCESS_KEY="+secretAccessKey,
		"AWS_SESSION_TOKEN="+sessionToken,
		"AWS_DEFAULT_REGION="+region,
	)

	return executeSecretsManagerCLI(cmd)
}

// GetSecretFromSecretsManager retrieves a secret value from AWS Secrets Manager
// given a secretArn. It returns the secret value as a JSON object (map[string]interface{}).
// This is a backward compatible function that uses context.Background()
func GetSecretFromSecretsManager(secretArn string) (map[string]interface{}, error) {
	return GetSecretFromSecretsManagerWithContext(context.Background(), secretArn)
}

// GetSecretFromSecretsManagerWithContext retrieves a secret value from AWS Secrets Manager
// given a secretArn and context using AWS CLI. It returns the secret value as a JSON object (map[string]interface{}).
func GetSecretFromSecretsManagerWithContext(ctx context.Context, secretArn string) (map[string]interface{}, error) {
	// Use AWS CLI to get secret
	cmd := exec.CommandContext(ctx, "aws", "secretsmanager", "get-secret-value", "--secret-id", secretArn, "--output", "json")
	return executeSecretsManagerCLI(cmd)
}

// ExtractCredentialsFromSecret extracts username, password, and distinguished name from the secret map
func ExtractCredentialsFromSecret(secretMap map[string]interface{}) (string, string, string, string, error) {
	if secretMap == nil {
		return "", "", "", "", fmt.Errorf("secret map is nil")
	}

	// Try to get username from the secret
	var username string
	if usernameVal, ok := secretMap["username"]; ok && usernameVal != nil {
		if usernameStr, ok := usernameVal.(string); ok && usernameStr != "" {
			username = usernameStr
		}
	}

	// Try alternate username field if primary is not found
	if username == "" {
		if usernameVal, ok := secretMap["usernameOfStandardUserAccount"]; ok && usernameVal != nil {
			if usernameStr, ok := usernameVal.(string); ok {
				username = usernameStr
			}
		}
	}

	// Get password from the secret - similar pattern
	var password string
	if passwordVal, ok := secretMap["password"]; ok && passwordVal != nil {
		if passwordStr, ok := passwordVal.(string); ok && passwordStr != "" {
			password = passwordStr
		}
	}

	if password == "" {
		if passwordVal, ok := secretMap["passwordOfStandardUserAccount"]; ok && passwordVal != nil {
			if passwordStr, ok := passwordVal.(string); ok {
				password = passwordStr
			}
		}
	}

	// Extract distinguished name if available
	var dn string
	if dnVal, ok := secretMap["distinguishedName"]; ok && dnVal != nil {
		if dnStr, ok := dnVal.(string); ok && dnStr != "" {
			dn = dnStr
		}
	}

	if dn == "" {
		if dnVal, ok := secretMap["distinguishedNameOfgMSA"]; ok && dnVal != nil {
			if dnStr, ok := dnVal.(string); ok {
				dn = dnStr
			}
		}
	}

	if dn != "" {
		log.Info("Found DN from Secrets Manager", "dn", dn)
	}

	var domainName string
	if domainNameVal, ok := secretMap["domainName"]; ok && domainNameVal != nil {
		if domainNameStr, ok := domainNameVal.(string); ok && domainNameStr != "" {
			domainName = domainNameStr
		}
	}

	// Validate required fields
	if username == "" {
		return "", "", "", "", fmt.Errorf("username not found in secret")
	}

	if password == "" {
		return "", "", "", "", fmt.Errorf("password not found in secret")
	}

	return username, password, domainName, dn, nil
}

// IsValidDomain checks if a domain name is valid
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// Basic domain validation - can be enhanced as needed
	parts := strings.Split(domain, ".")
	return len(parts) >= 2
}

// ContainsInvalidCharacters checks if a string contains invalid characters
func ContainsInvalidCharacters(s string, logMessage string) bool {
	log := logger.GetInstance()
	for _, char := range types.InvalidCharacters {
		if strings.ContainsRune(s, char) {
			log.Error("Contains invalid credentials in ", logMessage)
			return true
		}
	}
	return false
}

// ContainsInvalidCharactersInADAccountName checks if a username contains invalid characters
func ContainsInvalidCharactersInADAccountName(username string) bool {
	return ContainsInvalidCharacters(username, "AD account name")
}

// ContainsInvalidCharactersInCredentialSpec checks if a string contains invalid characters
func ContainsInvalidCharactersInCredentialSpec(s string) bool {
	return ContainsInvalidCharacters(s, "credential spec path")
}
