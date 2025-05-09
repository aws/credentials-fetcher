package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Mock the file operations for testing
func createTempConfigFile(t *testing.T, content string) (string, func()) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "ecs_config_test")
	require.NoError(t, err)

	// Create a temporary ECS config file
	tempConfigPath := filepath.Join(tempDir, "ecs.config")
	err = os.WriteFile(tempConfigPath, []byte(content), 0644)
	require.NoError(t, err)

	// Return the path and a cleanup function
	cleanup := func() {
		os.RemoveAll(tempDir)
	}

	return tempConfigPath, cleanup
}

func TestRetrieveVariableFromECSConfig(t *testing.T) {
	// Save the original function and restore it after tests
	originalOpen := osOpen
	defer func() { osOpen = originalOpen }()

	t.Run("Valid config file with variables", func(t *testing.T) {
		// Create a test config file with variables
		configContent := `
DOMAIN_CONTROLLER_GMSA=dc1.example.com
CF_GMSA_OU=OU=WebServers,DC=example,DC=com
CREDENTIALS_FETCHER_SECRET_NAME_FOR_DOMAINLESS_GMSA=my-secret
# This is a comment
EMPTY_VAR=
QUOTED_VAR="quoted value"
SPACED_VAR = spaced value
`
		configPath, cleanup := createTempConfigFile(t, configContent)
		defer cleanup()

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Test retrieving existing variables
		value, err := RetrieveVariableFromECSConfig("DOMAIN_CONTROLLER_GMSA")
		assert.NoError(t, err)
		assert.Equal(t, "dc1.example.com", value)

		value, err = RetrieveVariableFromECSConfig("CF_GMSA_OU")
		assert.NoError(t, err)
		assert.Equal(t, "OU=WebServers,DC=example,DC=com", value)

		value, err = RetrieveVariableFromECSConfig("CREDENTIALS_FETCHER_SECRET_NAME_FOR_DOMAINLESS_GMSA")
		assert.NoError(t, err)
		assert.Equal(t, "my-secret", value)

		// Test retrieving empty variable
		value, err = RetrieveVariableFromECSConfig("EMPTY_VAR")
		assert.NoError(t, err)
		assert.Equal(t, "", value)

		// Test retrieving quoted variable
		value, err = RetrieveVariableFromECSConfig("QUOTED_VAR")
		assert.NoError(t, err)
		assert.Equal(t, "\"quoted value\"", value)

		// Test retrieving variable with spaces
		value, err = RetrieveVariableFromECSConfig("SPACED_VAR")
		assert.NoError(t, err)
		assert.Equal(t, "spaced value", value)

		// Test retrieving non-existent variable
		value, err = RetrieveVariableFromECSConfig("NON_EXISTENT_VAR")
		assert.NoError(t, err)
		assert.Equal(t, "", value)
	})

	t.Run("Invalid config file format", func(t *testing.T) {
		// Create a test config file with invalid format
		configContent := `
VALID_VAR=valid_value
INVALID_LINE_NO_EQUALS
ANOTHER_VALID_VAR=another_value
`
		configPath, cleanup := createTempConfigFile(t, configContent)
		defer cleanup()

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Test retrieving variables from file with invalid lines
		value, err := RetrieveVariableFromECSConfig("VALID_VAR")
		assert.NoError(t, err)
		assert.Equal(t, "valid_value", value)

		value, err = RetrieveVariableFromECSConfig("ANOTHER_VALID_VAR")
		assert.NoError(t, err)
		assert.Equal(t, "another_value", value)
	})

	t.Run("Non-existent config file", func(t *testing.T) {
		// Mock the os.Open function to return an error
		osOpen = func(name string) (*os.File, error) {
			return nil, os.ErrNotExist
		}

		// Test retrieving variable from non-existent file
		_, err := RetrieveVariableFromECSConfig("ANY_VAR")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to open ECS config file")
	})
}

func TestGetConfigValue(t *testing.T) {
	// Save the original function and restore it after tests
	originalRetrieveVariableFromECSConfig := retrieveVariableFromECSConfig
	defer func() { retrieveVariableFromECSConfig = originalRetrieveVariableFromECSConfig }()

	t.Run("Config value exists", func(t *testing.T) {
		// Mock the RetrieveVariableFromECSConfig function
		retrieveVariableFromECSConfig = func(ecsVariableName string) (string, error) {
			if ecsVariableName == "TEST_KEY" {
				return "test_value", nil
			}
			return "", nil
		}

		// Test retrieving existing variable
		value, err := GetConfigValue("TEST_KEY")
		assert.NoError(t, err)
		assert.Equal(t, "test_value", value)
	})

	t.Run("Config value does not exist", func(t *testing.T) {
		// Mock the RetrieveVariableFromECSConfig function
		retrieveVariableFromECSConfig = func(ecsVariableName string) (string, error) {
			return "", nil
		}

		// Test retrieving non-existent variable
		value, err := GetConfigValue("NON_EXISTENT_KEY")
		assert.NoError(t, err)
		assert.Equal(t, "", value)
	})

	t.Run("Error reading config file", func(t *testing.T) {
		// Mock the RetrieveVariableFromECSConfig function to return an error
		retrieveVariableFromECSConfig = func(ecsVariableName string) (string, error) {
			return "", os.ErrNotExist
		}

		// Test retrieving variable with error
		_, err := GetConfigValue("ANY_KEY")
		assert.Error(t, err)
		assert.Equal(t, os.ErrNotExist, err)
	})
}
