package kerberos

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestGenerateKrbTicketFromMachineKeytab(t *testing.T) {
	// Create test cases
	testCases := []struct {
		name                  string
		domain                string
		mockCommandsExist     bool
		mockHostname          string
		mockRealmOutput       []byte
		mockRealmErr          error
		mockKeytabExists      bool
		mockKinitOutput       []byte
		mockKinitErr          error
		expectedError         bool
		expectedErrorContains string
		expectedPrincipal     string
	}{
		{
			name:                  "Missing required command",
			domain:                "example.com",
			mockCommandsExist:     false,
			mockHostname:          "testhost",
			mockRealmOutput:       []byte(""),
			mockRealmErr:          nil,
			mockKeytabExists:      true,
			mockKinitOutput:       []byte(""),
			mockKinitErr:          nil,
			expectedError:         true,
			expectedErrorContains: "required command not found",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock shell executor
			mockExecutor := new(MockExecutor)

			// Create a client with the mock executor
			client := &Client{
				shellExecutor: mockExecutor,
			}

			// Mock os.Hostname and os.Stat
			originalOsHostname := osHostname
			originalOsStat := osStat
			defer func() {
				osHostname = originalOsHostname
				osStat = originalOsStat
			}()

			// Set up mock for hostname
			osHostname = func() (string, error) {
				return tc.mockHostname, nil
			}

			// Set up mock for os.Stat to check if keytab exists
			osStat = func(name string) (os.FileInfo, error) {
				if name == "/etc/krb5.keytab" && !tc.mockKeytabExists {
					return nil, os.ErrNotExist
				}
				return nil, nil // Return nil, nil for exists
			}

			// Set up expectations for validateRequiredCommands
			requiredCommands := []string{"realm", "kinit", "ldapsearch"}
			for _, cmd := range requiredCommands {
				var err error
				if !tc.mockCommandsExist {
					err = errors.New("command not found")
				}
				mockExecutor.On("Execute",
					mock.Anything, // context
					"which",       // command
					cmd,           // args
				).Return([]byte(""), err).Maybe()
			}

			// If commands exist, set up expectations for getRealmName
			if tc.mockCommandsExist {
				// Mock for realm list command
				mockExecutor.On("Execute",
					mock.Anything, // context
					"bash",        // command
					"-c",          // args
					"realm list | grep 'realm-name' | cut -f2 -d: | tr -d ' ' | tr -d '\n'",
				).Return(tc.mockRealmOutput, tc.mockRealmErr).Maybe()

				// If realm list fails, mock for net ads info command
				if tc.mockRealmErr != nil {
					mockExecutor.On("Execute",
						mock.Anything, // context
						"bash",        // command
						"-c",          // args
						"net ads info | grep 'Realm' | cut -f2 -d: | tr -d ' ' | tr -d '\n'",
					).Return([]byte(""), errors.New("net ads info failed")).Maybe()
				}

				// If keytab exists and commands exist, set up expectations for kinit
				if tc.mockKeytabExists && tc.mockCommandsExist {
					// Calculate expected principal
					var expectedPrincipal string
					if len(tc.mockHostname) > 15 {
						expectedPrincipal = strings.ToUpper(tc.mockHostname[:15]) + "$@"
					} else {
						expectedPrincipal = strings.ToUpper(tc.mockHostname) + "$@"
					}

					if tc.mockRealmErr == nil && len(tc.mockRealmOutput) > 0 {
						expectedPrincipal += string(tc.mockRealmOutput)
					} else {
						expectedPrincipal += strings.ToUpper(tc.domain)
					}

					mockExecutor.On("Execute",
						mock.Anything,             // context
						"kinit",                   // command
						"-kt", "/etc/krb5.keytab", // args
						expectedPrincipal,
					).Return(tc.mockKinitOutput, tc.mockKinitErr)
				}
			}

			// Call GenerateKrbTicketFromMachineKeytab
			err := client.GenerateKrbTicketFromMachineKeytab(context.Background(), tc.domain)

			// Check results
			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
				if tc.expectedErrorContains != "" {
					assert.Contains(t, err.Error(), tc.expectedErrorContains, "Error message should contain expected text")
				}
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}

			// Verify that the mock was called as expected
			mockExecutor.AssertExpectations(t)
		})
	}
}

// Mock functions for os.Hostname and os.Stat
var osHostname = os.Hostname
var osStat = os.Stat
