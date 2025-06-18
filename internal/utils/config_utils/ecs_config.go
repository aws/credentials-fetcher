package config_utils

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

var log = logger.GetInstance()

// For testing purposes - allows mocking of os.Open
var osOpen = os.Open

// For testing purposes - allows mocking of os.Stat
var osStat = os.Stat

// For testing purposes - allows mocking of RetrieveVariableFromECSConfig
var retrieveVariableFromECSConfig = RetrieveVariableFromECSConfig

// For testing purposes - allows changing the credentials-fetcher.conf path
var credentialsFetcherConfPath = constants.CredentialsFetcherConfFilePath

// RetrieveVariableFromECSConfig retrieves a variable value from the ECS config file
// or from environment variables if not found in the config file
func RetrieveVariableFromECSConfig(ecsVariableName string) (string, error) {
	// Check if ECS config file exists
	if _, err := osStat(constants.ECSConfigFilePath); os.IsNotExist(err) {
		log.Info("ECS config file not found. Not operating in ECS mode.", "path", constants.ECSConfigFilePath)
		return "", nil // Return empty string but no error to continue function
	}

	// Open the ECS config file
	file, err := osOpen(constants.ECSConfigFilePath)
	if err != nil {
		log.Error("Failed to open ECS config file", "path", constants.ECSConfigFilePath, "error", err)
		return "", fmt.Errorf("failed to open ECS config file: %w", err)
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			fmt.Printf("%s", err.Error())
		}
	}(file)

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Split the line by '='
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			log.Warn("Invalid configuration format in ECS config file", "line", line)
			continue
		}

		// Trim whitespace from key and value
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Check if this is the variable we're looking for
		if key == ecsVariableName {
			log.Debug("Found variable in ECS config file", "key", key, "value", value)
			return value, nil
		}
	}

	if err := scanner.Err(); err != nil {
		log.Error("Error reading ECS config file", "error", err)
		return "", fmt.Errorf("error reading ECS config file: %w", err)
	}

	log.Debug("Variable not found in ECS config file", "variable", ecsVariableName)
	return "", nil
}

// GetConfigValue retrieves a configuration value from the ECS config file only
func GetConfigValue(key string) (string, error) {
	// Check ECS config file
	value, err := retrieveVariableFromECSConfig(key)
	if err != nil {
		return "", err
	}

	if value != "" {
		log.Debug("Found configuration in ECS config file", "key", key)
	} else {
		log.Debug("Configuration not found in ECS config file", "key", key)
	}

	return value, nil
}

// GetValueFromCredentialsFetcherConf retrieves a value for the specified key from the credentials-fetcher.conf file
func GetValueFromCredentialsFetcherConf(key string) string {
	// Check if config file exists
	_, err := osStat(credentialsFetcherConfPath)
	if os.IsNotExist(err) {
		log.Debug("Credentials fetcher config file does not exist", "path", credentialsFetcherConfPath)
		return ""
	}

	// Open the config file
	file, err := osOpen(credentialsFetcherConfPath)
	if err != nil {
		log.Error("Failed to open credentials fetcher config file", "path", credentialsFetcherConfPath, "error", err)
		return ""
	}
	defer func() {
		if err := file.Close(); err != nil {
			log.Error("Failed to close credentials fetcher config file", "path", credentialsFetcherConfPath, "error", err)
		}
	}()

	// Read the file line by line
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split the line by '='
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		// Trim whitespace from key and value
		configKey := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Check if this is the key we're looking for
		if configKey == key {
			// Remove quotes if present
			value = strings.Trim(value, "\"")
			log.Debug("Found key in config file", "key", key, "value", value)
			return value
		}
	}

	if err := scanner.Err(); err != nil {
		log.Error("Error reading credentials fetcher config file", "error", err)
	}

	log.Debug("Key not found in config file", "key", key)
	return ""
}

// GetSecretNameFromConf retrieves the CFGmsaSecretName value from the credentials-fetcher.conf file
func GetSecretNameFromConf() string {
	return GetValueFromCredentialsFetcherConf("CFGmsaSecretName")
}

// IsRunRenewalNonDomainJoinedEnabled checks if the RunRenewalNonDomainJoined flag is set to true
// in the credentials-fetcher.conf file
func IsRunRenewalNonDomainJoinedEnabled() bool {
	value := GetValueFromCredentialsFetcherConf("RunRenewalNonDomainJoined")
	return strings.ToLower(value) == "true"
}
