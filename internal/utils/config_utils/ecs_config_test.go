package config_utils

import (
	"fmt"
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
	err = os.WriteFile(tempConfigPath, []byte(content), 0644) /* #nosec */
	require.NoError(t, err)

	// Return the path and a cleanup function
	cleanup := func() {
		err := os.RemoveAll(tempDir)
		if err != nil {
			fmt.Printf("%s", err.Error())
			return
		}
	}

	return tempConfigPath, cleanup
}

// Create a temporary credentials-fetcher.conf file for testing
func createTempCredentialsFetcherConfFile(t *testing.T, content string) (string, func()) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "credentials_fetcher_conf_test")
	require.NoError(t, err)

	// Create a temporary credentials-fetcher.conf file
	tempConfigPath := filepath.Join(tempDir, "credentials-fetcher.conf")
	err = os.WriteFile(tempConfigPath, []byte(content), 0644) /* #nosec */
	require.NoError(t, err)

	// Return the path and a cleanup function
	cleanup := func() {
		err := os.RemoveAll(tempDir)
		if err != nil {
			fmt.Printf("%s", err.Error())
			return
		}
	}

	return tempConfigPath, cleanup
}

func TestRetrieveVariableFromECSConfig(t *testing.T) {
	// Save the original functions and restore them after tests
	originalOpen := osOpen
	originalStat := osStat
	defer func() {
		osOpen = originalOpen
		osStat = originalStat
	}()

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

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
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

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
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

		// Mock the os.Stat function to indicate the file doesn't exist
		osStat = func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		}

		// Test retrieving variable from non-existent file
		_, err := RetrieveVariableFromECSConfig("ANY_VAR")
		assert.NoError(t, err) // We expect no error because the function handles this case gracefully
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

func TestGetValueFromCredentialsFetcherConf(t *testing.T) {
	// Save the original values and restore them after the test
	originalPath := credentialsFetcherConfPath
	originalOpen := osOpen
	originalStat := osStat
	defer func() {
		credentialsFetcherConfPath = originalPath
		osOpen = originalOpen
		osStat = originalStat
	}()

	t.Run("Config file exists with variables", func(t *testing.T) {
		// Create a test config file
		configContent := `
# Credentials Fetcher Configuration File

# Run renewal for non-domain joined instances
RunRenewalNonDomainJoined = true

# gMSA Secret Name in AWS Secrets Manager
CFGmsaSecretName = "aws/contoso/gmsa"

# LDAP Search Timeout Interval
LDAPSearchTimeout = 30

# Empty value
EmptyValue = 

# Quoted value with spaces
QuotedValue = "this is a quoted value"
`
		configPath, cleanup := createTempCredentialsFetcherConfFile(t, configContent)
		defer cleanup()

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
		}

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Test retrieving existing variables
		value := GetValueFromCredentialsFetcherConf("RunRenewalNonDomainJoined")
		assert.Equal(t, "true", value)

		value = GetValueFromCredentialsFetcherConf("CFGmsaSecretName")
		assert.Equal(t, "aws/contoso/gmsa", value)

		value = GetValueFromCredentialsFetcherConf("LDAPSearchTimeout")
		assert.Equal(t, "30", value)

		// Test retrieving empty value
		value = GetValueFromCredentialsFetcherConf("EmptyValue")
		assert.Equal(t, "", value)

		// Test retrieving quoted value
		value = GetValueFromCredentialsFetcherConf("QuotedValue")
		assert.Equal(t, "this is a quoted value", value)

		// Test retrieving non-existent variable
		value = GetValueFromCredentialsFetcherConf("NonExistentKey")
		assert.Equal(t, "", value)
	})

	t.Run("Config file with invalid format", func(t *testing.T) {
		// Create a test config file with invalid format
		configContent := `
ValidKey = ValidValue
InvalidLineNoEquals
AnotherValidKey = AnotherValue
`
		configPath, cleanup := createTempCredentialsFetcherConfFile(t, configContent)
		defer cleanup()

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
		}

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Test retrieving variables from file with invalid lines
		value := GetValueFromCredentialsFetcherConf("ValidKey")
		assert.Equal(t, "ValidValue", value)

		value = GetValueFromCredentialsFetcherConf("AnotherValidKey")
		assert.Equal(t, "AnotherValue", value)
	})

	t.Run("Config file does not exist", func(t *testing.T) {
		// Set the path to a non-existent file
		credentialsFetcherConfPath = "/non/existent/path/credentials-fetcher.conf"

		// Mock the os.Stat function to indicate the file doesn't exist
		osStat = func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		}

		// Test retrieving variable when file doesn't exist
		value := GetValueFromCredentialsFetcherConf("AnyKey")
		assert.Equal(t, "", value)
	})

	t.Run("Error opening config file", func(t *testing.T) {
		// Set the path to any file
		credentialsFetcherConfPath = "/tmp/credentials-fetcher.conf"

		// Mock osOpen to return an error
		osOpen = func(name string) (*os.File, error) {
			return nil, fmt.Errorf("permission denied")
		}

		// Test retrieving variable when file can't be opened
		value := GetValueFromCredentialsFetcherConf("AnyKey")
		assert.Equal(t, "", value)
	})
}

func TestGetSecretNameFromConf(t *testing.T) {
	// Save the original values
	originalPath := credentialsFetcherConfPath
	originalOpen := osOpen
	originalStat := osStat

	// Restore the original values after the test
	defer func() {
		credentialsFetcherConfPath = originalPath
		osOpen = originalOpen
		osStat = originalStat
	}()

	t.Run("Secret name exists", func(t *testing.T) {
		// Create a test config file
		configContent := `
# Credentials Fetcher Configuration File
CFGmsaSecretName = "aws/test/secret"
`
		configPath, cleanup := createTempCredentialsFetcherConfFile(t, configContent)
		defer cleanup()

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
		}

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Test retrieving the secret name
		secretName := GetSecretNameFromConf()
		assert.Equal(t, "aws/test/secret", secretName)
	})

	t.Run("Secret name does not exist", func(t *testing.T) {
		// Create a test config file without the secret name
		configContent := `
# Credentials Fetcher Configuration File
SomeOtherKey = "some value"
`
		configPath, cleanup := createTempCredentialsFetcherConfFile(t, configContent)
		defer cleanup()

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
		}

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Test retrieving non-existent secret name
		secretName := GetSecretNameFromConf()
		assert.Equal(t, "", secretName)
	})
}

func TestGetLdapTimeoutFromConf(t *testing.T) {
	// Save the original values
	originalPath := credentialsFetcherConfPath
	originalOpen := osOpen
	originalStat := osStat

	// Restore the original values after the test
	defer func() {
		credentialsFetcherConfPath = originalPath
		osOpen = originalOpen
		osStat = originalStat
	}()

	t.Run("Timeout variable exists and is vali[d", func(t *testing.T) {
		// Create a test config file
		configContent := `
# Credentials Fetcher Configuration File
LDAPSearchTimeout = "30"
`
		configPath, cleanup := createTempCredentialsFetcherConfFile(t, configContent)
		defer cleanup()

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
		}

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Test retrieving the timeout value
		timeout, err := GetLdapTimeoutFromConf()
		assert.Equal(t, "30", timeout)
		assert.Nil(t, err)
	})

	t.Run("Timeout variable does not exist", func(t *testing.T) {
		// Create a test config file without the secret name
		configContent := `
# Credentials Fetcher Configuration File
SomeOtherKey = "some value"
`
		configPath, cleanup := createTempCredentialsFetcherConfFile(t, configContent)
		defer cleanup()

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
		}

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Test retrieving non-existent timeout value - should return default of "5"
		timeout, err := GetLdapTimeoutFromConf()
		assert.NoError(t, err)
		assert.Equal(t, "5", timeout)
	})

	t.Run("Timeout variable exists and is malformed", func(t *testing.T) {
		// Create a test config file without the secret name
		configContent := `
# Credentials Fetcher Configuration File
LDAPSearchTimeout = "some value"
`
		configPath, cleanup := createTempCredentialsFetcherConfFile(t, configContent)
		defer cleanup()

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
		}

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Test retrieving malformed timeout value
		timeout, err := GetLdapTimeoutFromConf()
		assert.Error(t, err)
		assert.Empty(t, timeout)
	})

	t.Run("Timeout variable exists and is negative", func(t *testing.T) {
		// Create a test config file without the secret name
		configContent := `
# Credentials Fetcher Configuration File
LDAPSearchTimeout = "-2"
`
		configPath, cleanup := createTempCredentialsFetcherConfFile(t, configContent)
		defer cleanup()

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
		}

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Test retrieving malformed timeout value
		timeout, err := GetLdapTimeoutFromConf()
		assert.Error(t, err)
		assert.Empty(t, timeout)
	})

	t.Run("Timeout variable exists and is greater than the max", func(t *testing.T) {
		// Create a test config file without the secret name
		configContent := `
# Credentials Fetcher Configuration File
LDAPSearchTimeout = "72"
`
		configPath, cleanup := createTempCredentialsFetcherConfFile(t, configContent)
		defer cleanup()

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Mock the os.Stat function to indicate the file exists
		osStat = func(name string) (os.FileInfo, error) {
			return os.Stat(configPath)
		}

		// Mock the os.Open function to use our test file
		osOpen = func(name string) (*os.File, error) {
			return os.Open(configPath)
		}

		// Set the path to our test file
		credentialsFetcherConfPath = configPath

		// Test retrieving malformed timeout value
		timeout, err := GetLdapTimeoutFromConf()
		assert.Error(t, err)
		assert.Empty(t, timeout)
	})
}

func TestIsRunRenewalNonDomainJoinedEnabled(t *testing.T) {
	// Save the original values
	originalPath := credentialsFetcherConfPath
	originalOpen := osOpen
	originalStat := osStat

	// Restore the original values after the test
	defer func() {
		credentialsFetcherConfPath = originalPath
		osOpen = originalOpen
		osStat = originalStat
	}()

	testCases := []struct {
		name           string
		configContent  string
		expectedResult bool
	}{
		{
			name: "Value is true",
			configContent: `
# Credentials Fetcher Configuration File
RunRenewalNonDomainJoined = true
`,
			expectedResult: true,
		},
		{
			name: "Value is TRUE (uppercase)",
			configContent: `
# Credentials Fetcher Configuration File
RunRenewalNonDomainJoined = TRUE
`,
			expectedResult: true,
		},
		{
			name: "Value is True (mixed case)",
			configContent: `
# Credentials Fetcher Configuration File
RunRenewalNonDomainJoined = True
`,
			expectedResult: true,
		},
		{
			name: "Value is false",
			configContent: `
# Credentials Fetcher Configuration File
RunRenewalNonDomainJoined = false
`,
			expectedResult: false,
		},
		{
			name: "Value is something else",
			configContent: `
# Credentials Fetcher Configuration File
RunRenewalNonDomainJoined = yes
`,
			expectedResult: false,
		},
		{
			name: "Key does not exist",
			configContent: `
# Credentials Fetcher Configuration File
SomeOtherKey = value
`,
			expectedResult: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a test config file
			configPath, cleanup := createTempCredentialsFetcherConfFile(t, tc.configContent)
			defer cleanup()

			// Set the path to our test file
			credentialsFetcherConfPath = configPath

			// Mock the os.Stat function to indicate the file exists
			osStat = func(name string) (os.FileInfo, error) {
				return os.Stat(configPath)
			}

			// Mock the os.Open function to use our test file
			osOpen = func(name string) (*os.File, error) {
				return os.Open(configPath)
			}

			// Test the function
			result := IsRunRenewalNonDomainJoinedEnabled()
			assert.Equal(t, tc.expectedResult, result)
		})
	}

	t.Run("Config file does not exist", func(t *testing.T) {
		// Set the path to a non-existent file
		credentialsFetcherConfPath = "/non/existent/path/credentials-fetcher.conf"

		// Mock the os.Stat function to indicate the file doesn't exist
		osStat = func(name string) (os.FileInfo, error) {
			return nil, os.ErrNotExist
		}

		// Test the function when file doesn't exist
		result := IsRunRenewalNonDomainJoinedEnabled()
		assert.False(t, result)
	})
}
