package debug_utils

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSimulateDebugError(t *testing.T) {
	tests := []struct {
		name        string
		logLevel    string
		simTarget   string
		operation   string
		expectError bool
		expectedMsg string
	}{
		{
			name:        "no env vars set",
			logLevel:    "",
			simTarget:   "",
			operation:   SimulateSetupKerberosFile,
			expectError: false,
		},
		{
			name:        "debug mode but no simulate target",
			logLevel:    "debug",
			simTarget:   "",
			operation:   SimulateSetupKerberosFile,
			expectError: false,
		},
		{
			name:        "simulate target set but not in debug mode",
			logLevel:    "info",
			simTarget:   SimulateSetupKerberosFile,
			operation:   SimulateSetupKerberosFile,
			expectError: false,
		},
		{
			name:        "simulate target set but log level not set",
			logLevel:    "",
			simTarget:   SimulateSetupKerberosFile,
			operation:   SimulateSetupKerberosFile,
			expectError: false,
		},
		{
			name:        "debug mode with matching setup_kerberos_file target",
			logLevel:    "debug",
			simTarget:   SimulateSetupKerberosFile,
			operation:   SimulateSetupKerberosFile,
			expectError: true,
			expectedMsg: "simulated debug error in setup_kerberos_file",
		},
		{
			name:        "debug mode with matching create_ticket_gmsa target",
			logLevel:    "debug",
			simTarget:   SimulateCreateTicketGMSA,
			operation:   SimulateCreateTicketGMSA,
			expectError: true,
			expectedMsg: "simulated debug error in create_ticket_gmsa",
		},
		{
			name:        "debug mode with matching get_distinguished_name target",
			logLevel:    "debug",
			simTarget:   SimulateGetDistinguishedName,
			operation:   SimulateGetDistinguishedName,
			expectError: true,
			expectedMsg: "simulated debug error in get_distinguished_name",
		},
		{
			name:        "debug mode with non-matching target",
			logLevel:    "debug",
			simTarget:   SimulateCreateTicketGMSA,
			operation:   SimulateSetupKerberosFile,
			expectError: false,
		},
		{
			name:        "debug mode with whitespace-padded target",
			logLevel:    "debug",
			simTarget:   "  " + SimulateCreateTicketGMSA + "  ",
			operation:   SimulateCreateTicketGMSA,
			expectError: true,
			expectedMsg: "simulated debug error in create_ticket_gmsa",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ResetDebugErrorCount()

			origLogLevel := os.Getenv("LOG_LEVEL")
			origSimTarget := os.Getenv(envDebugSimulateError)
			defer func() {
				require.NoError(t, os.Setenv("LOG_LEVEL", origLogLevel))
				require.NoError(t, os.Setenv(envDebugSimulateError, origSimTarget))
			}()

			if tt.logLevel != "" {
				require.NoError(t, os.Setenv("LOG_LEVEL", tt.logLevel))
			} else {
				require.NoError(t, os.Unsetenv("LOG_LEVEL"))
			}
			if tt.simTarget != "" {
				require.NoError(t, os.Setenv(envDebugSimulateError, tt.simTarget))
			} else {
				require.NoError(t, os.Unsetenv(envDebugSimulateError))
			}

			err := SimulateDebugError(tt.operation)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSimulateDebugError_InvocationLimit(t *testing.T) {
	ResetDebugErrorCount()

	origLogLevel := os.Getenv("LOG_LEVEL")
	origSimTarget := os.Getenv(envDebugSimulateError)
	defer func() {
		require.NoError(t, os.Setenv("LOG_LEVEL", origLogLevel))
		require.NoError(t, os.Setenv(envDebugSimulateError, origSimTarget))
	}()

	require.NoError(t, os.Setenv("LOG_LEVEL", "debug"))
	require.NoError(t, os.Setenv(envDebugSimulateError, SimulateCreateTicketGMSA))

	for i := 1; i <= maxDebugErrorSimulations; i++ {
		err := SimulateDebugError(SimulateCreateTicketGMSA)
		assert.Error(t, err, "invocation %d should return error", i)
	}

	for i := 1; i <= 3; i++ {
		err := SimulateDebugError(SimulateCreateTicketGMSA)
		assert.NoError(t, err, "invocation %d past limit should return nil", maxDebugErrorSimulations+i)
	}
}

func TestResetDebugErrorCount(t *testing.T) {
	ResetDebugErrorCount()

	origLogLevel := os.Getenv("LOG_LEVEL")
	origSimTarget := os.Getenv(envDebugSimulateError)
	defer func() {
		require.NoError(t, os.Setenv("LOG_LEVEL", origLogLevel))
		require.NoError(t, os.Setenv(envDebugSimulateError, origSimTarget))
	}()

	require.NoError(t, os.Setenv("LOG_LEVEL", "debug"))
	require.NoError(t, os.Setenv(envDebugSimulateError, SimulateSetupKerberosFile))

	for i := 0; i < maxDebugErrorSimulations; i++ {
		err := SimulateDebugError(SimulateSetupKerberosFile)
		assert.Error(t, err)
	}
	err := SimulateDebugError(SimulateSetupKerberosFile)
	assert.NoError(t, err, "should stop after limit")

	ResetDebugErrorCount()

	err = SimulateDebugError(SimulateSetupKerberosFile)
	assert.Error(t, err, "should simulate again after reset")
}
