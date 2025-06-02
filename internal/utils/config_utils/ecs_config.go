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

// For testing purposes - allows mocking of RetrieveVariableFromECSConfig
var retrieveVariableFromECSConfig = RetrieveVariableFromECSConfig

// RetrieveVariableFromECSConfig retrieves a variable value from the ECS config file
// This is a Go implementation of the C++ function retrieve_variable_from_ecs_config
func RetrieveVariableFromECSConfig(ecsVariableName string) (string, error) {
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
