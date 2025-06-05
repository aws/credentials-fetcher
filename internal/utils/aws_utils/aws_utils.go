package aws_utils

import (
	"encoding/json"
	"fmt"
	"strings"

	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

var log = logger.GetInstance()

// GetSecretFromSecretsManager retrieves a secret value from AWS Secrets Manager
// given a secretArn. It returns the secret value as a JSON object (map[string]interface{}).
func GetSecretFromSecretsManager(secretArn string) (map[string]interface{}, error) {
	// Create a new AWS session
	sess, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}
	log.Info("Created AWS session to retrieve secret from Secrets Manager", "secretArn", secretArn)
	// Create a Secrets Manager client
	svc := secretsmanager.New(sess)

	return getSecretWithClient(svc, secretArn)
}

// getSecretWithClient is a helper function that uses the provided Secrets Manager client
// to retrieve a secret. This function is used by both the main code and tests.
func getSecretWithClient(svc secretsmanageriface.SecretsManagerAPI, secretArn string) (map[string]interface{}, error) {
	// Create the input for GetSecretValue
	input := &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretArn),
	}

	// Call GetSecretValue API
	result, err := svc.GetSecretValue(input)
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

// GetSecretFromSecretsManagerWithSession retrieves a secret value from AWS Secrets Manager
// using the provided AWS session. It returns the secret value as a JSON object (map[string]interface{}).
func GetSecretFromSecretsManagerWithSession(sess *session.Session, secretArn string) (map[string]interface{}, error) {
	log.Info("Retrieving secret from Secrets Manager", "secretArn", secretArn)

	// Create a Secrets Manager client with the provided session
	svc := secretsmanager.New(sess)

	return getSecretWithClient(svc, secretArn)
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
