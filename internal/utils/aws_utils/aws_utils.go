package aws_utils

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

var log = logger.GetInstance()

// secretsManagerClient is an interface for AWS Secrets Manager client
type secretsManagerClient interface {
	GetSecretValue(ctx context.Context, input *secretsmanager.GetSecretValueInput, optFns ...func(*secretsmanager.Options)) (*secretsmanager.GetSecretValueOutput, error)
}

// GetSecretFromSecretsManager retrieves a secret value from AWS Secrets Manager
// given a secretArn. It returns the secret value as a JSON object (map[string]interface{}).
// This is a backward compatible function that uses context.Background()
func GetSecretFromSecretsManager(secretArn string) (map[string]interface{}, error) {
	return GetSecretFromSecretsManagerWithContext(context.Background(), secretArn)
}

// GetSecretFromSecretsManagerWithContext retrieves a secret value from AWS Secrets Manager
// given a secretArn and context. It returns the secret value as a JSON object (map[string]interface{}).
func GetSecretFromSecretsManagerWithContext(ctx context.Context, secretArn string) (map[string]interface{}, error) {
	// Parse region from ARN
	region, err := parseRegionFromARN(secretArn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse region from ARN: %v", err)
	}
	log.Debug("Parsed region from Secret ARN: ", "region", region)

	// Create a new AWS config with the parsed region
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(region))
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS config: %v", err)
	}

	// Create Secrets Manager client
	svc := secretsmanager.NewFromConfig(cfg)
	log.Info("Created AWS config to retrieve secret from Secrets Manager", "secretArn", secretArn, "region", region)

	return getSecretWithClient(ctx, svc, secretArn)
}

// getSecretWithClient is a helper function that uses the provided Secrets Manager client
// to retrieve a secret. This function is used by both the main code and tests.
func getSecretWithClient(ctx context.Context, svc secretsManagerClient, secretArn string) (map[string]interface{}, error) {
	// Create the input for GetSecretValue
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	}

	// Call GetSecretValue API
	result, err := svc.GetSecretValue(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to get secret value: %v", err)
	}

	// Parse the JSON string into a map
	var secretMap map[string]interface{}
	if err := json.Unmarshal([]byte(*result.SecretString), &secretMap); err != nil {
		return nil, fmt.Errorf("failed to parse secret JSON: %v", err)
	}

	return secretMap, nil
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

// GetSecretFromSecretsManagerWithConfig retrieves a secret value from AWS Secrets Manager
// using the provided AWS config. It returns the secret value as a JSON object (map[string]interface{}).
func GetSecretFromSecretsManagerWithConfig(ctx context.Context, cfg aws.Config, secretArn string) (map[string]interface{}, error) {
	log.Info("Retrieving secret from Secrets Manager", "secretArn", secretArn)

	// Create a Secrets Manager client with the provided config
	svc := secretsmanager.NewFromConfig(cfg)

	return getSecretWithClient(ctx, svc, secretArn)
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

// parseRegionFromARN extracts the region from an AWS ARN
func parseRegionFromARN(arn string) (string, error) {
	parts := strings.Split(arn, ":")
	if len(parts) < 4 {
		return "", fmt.Errorf("invalid ARN format: %s", arn)
	}
	return parts[3], nil
}
