package aws_utils

import (
	"encoding/json"
	"fmt"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/secretsmanager"
	"github.com/aws/aws-sdk-go/service/secretsmanager/secretsmanageriface"
)

// GetSecretFromSecretsManager retrieves a secret value from AWS Secrets Manager
// given a secretArn. It returns the secret value as a JSON object (map[string]interface{}).
func GetSecretFromSecretsManager(secretArn string) (map[string]interface{}, error) {
	// Create a new AWS session
	sess, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %v", err)
	}

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
