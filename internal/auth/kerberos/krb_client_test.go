package kerberos

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

// MockKlistExecutor mocks the KlistExecutor interface for testing
type MockKlistExecutor struct {
	Output string
	Err    error
}

func (m *MockKlistExecutor) executeKlist(path string) (string, error) {
	return m.Output, m.Err
}

// Test data
var validKlistCompactOutput = `Ticket cache: FILE:/path/to/ticket
Default principal: user123@EXAMPLE.COM

Valid starting     Expires            Service principal
05/15/2023 09:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 05/22/2023 09:00:00
`

var validKlistMultilineOutput = `Ticket cache: FILE:/path/to/ticket
Default principal: user123@EXAMPLE.COM

Valid starting     Expires            Service principal
05/15/2023 09:00:00
                 05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 05/22/2023 09:00:00
`

var validKlistMachineOutput = `Ticket cache: FILE:/path/to/ticket
Default principal: machine$@EXAMPLE.COM

Valid starting     Expires            Service principal
05/15/2023 09:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 05/22/2023 09:00:00
`

var missingPrincipalOutput = `Ticket cache: FILE:/path/to/ticket

Valid starting     Expires            Service principal
05/15/2023 09:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 05/22/2023 09:00:00
`

func TestGetTicket(t *testing.T) {
	testCases := []struct {
		name           string
		mockOutput     string
		mockErr        error
		expectedError  bool
		expectedTicket *types.Ticket
	}{
		{
			name:          "Valid ticket (compact format)",
			mockOutput:    validKlistCompactOutput,
			mockErr:       nil,
			expectedError: false,
			expectedTicket: &types.Ticket{
				Path:           "/path/to/ticket",
				Principal:      "user123",
				Domain:         "EXAMPLE.COM",
				CreationTime:   parseTime("05/15/2023 09:00:00"),
				ExpirationTime: parseTime("05/16/2023 10:00:00"),
				RenewUntil:     parseTime("05/22/2023 09:00:00"),
			},
		},
		{
			name:          "Valid ticket (multiline format)",
			mockOutput:    validKlistMultilineOutput,
			mockErr:       nil,
			expectedError: false,
			expectedTicket: &types.Ticket{
				Path:           "/path/to/ticket",
				Principal:      "user123",
				Domain:         "EXAMPLE.COM",
				CreationTime:   parseTime("05/15/2023 09:00:00"),
				ExpirationTime: parseTime("05/16/2023 10:00:00"),
				RenewUntil:     parseTime("05/22/2023 09:00:00"),
			},
		},
		{
			name:           "Klist command failure",
			mockOutput:     "",
			mockErr:        errors.New("klist command failed"),
			expectedError:  true,
			expectedTicket: nil,
		},
		{
			name:           "Missing principal",
			mockOutput:     missingPrincipalOutput,
			mockErr:        nil,
			expectedError:  true,
			expectedTicket: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a mock executor
			mockExecutor := &MockKlistExecutor{
				Output: tc.mockOutput,
				Err:    tc.mockErr,
			}

			// Create a client
			client := NewClient()

			// Call GetTicket
			ticket, ticketInfo, err := client.GetTicket("/path/to/ticket", mockExecutor)

			// Check results
			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, ticket, "Expected nil ticket but got a ticket")
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if ticket == nil {
					t.Errorf("Expected ticket but got nil")
				}
				if ticketInfo == nil {
					t.Errorf("Expected ticketInfo but got nil")
				}
				if ticket != nil && ticket.Principal != "user123" && ticket.Principal != "machine$" {
					t.Errorf("Expected principal 'user123' or 'machine$' but got '%s'", ticket.Principal)
				}
			}
		})
	}
}

func TestGetTicketsFromMetadata(t *testing.T) {
	testCases := []struct {
		name                string
		mockTicketInfos     []*types.TicketInfo
		mockReadErr         error
		mockKlistOutput     string
		mockKlistErr        error
		expectedTicketCount int
		expectedError       bool
	}{
		{
			name: "Valid metadata with ticket",
			mockTicketInfos: []*types.TicketInfo{
				{
					KrbFilePath:        "/path/to/ticket1",
					ServiceAccountName: "user123",
					DomainName:         "EXAMPLE.COM",
				},
			},
			mockReadErr:         nil,
			mockKlistOutput:     validKlistCompactOutput,
			mockKlistErr:        nil,
			expectedTicketCount: 1,
			expectedError:       false,
		},
		{
			name:                "Metadata read error",
			mockTicketInfos:     nil,
			mockReadErr:         errors.New("failed to read metadata"),
			mockKlistOutput:     "",
			mockKlistErr:        nil,
			expectedTicketCount: 0,
			expectedError:       true,
		},
		{
			name:                "Empty metadata",
			mockTicketInfos:     []*types.TicketInfo{},
			mockReadErr:         nil,
			mockKlistOutput:     "",
			mockKlistErr:        nil,
			expectedTicketCount: 0,
			expectedError:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Save original functions and restore them after the test
			originalReadMetadataJSONFunc := readMetadataJSONFunc
			originalDefaultExecutor := defaultExecutor
			defer func() {
				readMetadataJSONFunc = originalReadMetadataJSONFunc
				defaultExecutor = originalDefaultExecutor
			}()

			// Set up mock functions
			readMetadataJSONFunc = func(filePath string) ([]*types.TicketInfo, error) {
				return tc.mockTicketInfos, tc.mockReadErr
			}

			// Create a mock executor and replace the default one
			defaultExecutor = &MockKlistExecutor{
				Output: tc.mockKlistOutput,
				Err:    tc.mockKlistErr,
			}

			// Create a client
			client := NewClient()

			// Call GetTicketsFromMetadata
			tickets, ticketInfos, err := client.GetTicketsFromMetadata("/path/to/metadata.json")

			// Check results
			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, tickets, "Expected nil tickets but got tickets")
				assert.Nil(t, ticketInfos, "Expected nil ticketInfos but got ticketInfos")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.Equal(t, tc.expectedTicketCount, len(tickets), "Unexpected number of tickets")
				assert.Equal(t, tc.expectedTicketCount, len(ticketInfos), "Unexpected number of ticketInfos")
			}
		})
	}
}

func TestGetAllTicketsFromDirectory(t *testing.T) {
	testCases := []struct {
		name                string
		mockMetadataFiles   []string
		mockGetPathsErr     error
		mockTicketInfos     []*types.TicketInfo
		mockReadErr         error
		mockKlistOutput     string
		mockKlistErr        error
		expectedTicketCount int
		expectedError       bool
	}{
		{
			name:              "Valid directory with metadata",
			mockMetadataFiles: []string{"/path/to/metadata.json"},
			mockGetPathsErr:   nil,
			mockTicketInfos: []*types.TicketInfo{
				{
					KrbFilePath:        "/path/to/ticket1",
					ServiceAccountName: "user123",
					DomainName:         "EXAMPLE.COM",
				},
			},
			mockReadErr:         nil,
			mockKlistOutput:     validKlistCompactOutput,
			mockKlistErr:        nil,
			expectedTicketCount: 1,
			expectedError:       false,
		},
		{
			name:                "Error getting metadata files",
			mockMetadataFiles:   nil,
			mockGetPathsErr:     errors.New("failed to get metadata files"),
			mockTicketInfos:     nil,
			mockReadErr:         nil,
			mockKlistOutput:     "",
			mockKlistErr:        nil,
			expectedTicketCount: 0,
			expectedError:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Save original functions and restore them after the test
			originalGetMetadataFilePathsFunc := getMetadataFilePathsFunc
			originalReadMetadataJSONFunc := readMetadataJSONFunc
			originalDefaultExecutor := defaultExecutor
			defer func() {
				getMetadataFilePathsFunc = originalGetMetadataFilePathsFunc
				readMetadataJSONFunc = originalReadMetadataJSONFunc
				defaultExecutor = originalDefaultExecutor
			}()

			// Set up mock functions
			getMetadataFilePathsFunc = func(directory string) ([]string, error) {
				return tc.mockMetadataFiles, tc.mockGetPathsErr
			}

			readMetadataJSONFunc = func(filePath string) ([]*types.TicketInfo, error) {
				return tc.mockTicketInfos, tc.mockReadErr
			}

			// Create a mock executor and replace the default one
			defaultExecutor = &MockKlistExecutor{
				Output: tc.mockKlistOutput,
				Err:    tc.mockKlistErr,
			}

			// Create a client
			client := NewClient()

			// Call GetAllTicketsFromDirectory
			tickets, ticketInfos, err := client.GetAllTicketsFromDirectory("/path/to/directory")

			// Check results
			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, tickets, "Expected nil tickets but got tickets")
				assert.Nil(t, ticketInfos, "Expected nil ticketInfos but got ticketInfos")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.Equal(t, tc.expectedTicketCount, len(tickets), "Unexpected number of tickets")
				assert.Equal(t, tc.expectedTicketCount, len(ticketInfos), "Unexpected number of ticketInfos")
			}
		})
	}
}

func TestParseKlistOutput(t *testing.T) {
	testCases := []struct {
		name          string
		output        string
		expectedError bool
	}{
		{
			name:          "Valid output with standard principal",
			output:        validKlistCompactOutput,
			expectedError: false,
		},
		{
			name:          "Valid output with machine account",
			output:        validKlistMachineOutput,
			expectedError: false,
		},
		{
			name:          "Missing principal",
			output:        missingPrincipalOutput,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ticket, ticketInfo, err := parseKlistOutput(tc.output, "/path/to/ticket")

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, ticket, "Expected nil ticket but got a ticket")
				assert.Nil(t, ticketInfo, "Expected nil ticketInfo but got a ticketInfo")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.NotNil(t, ticket, "Expected a ticket but got nil")
				assert.NotNil(t, ticketInfo, "Expected a ticketInfo but got nil")
			}
		})
	}
}

func TestParsePrincipalInfo(t *testing.T) {
	testCases := []struct {
		name           string
		lines          []string
		expectedError  bool
		expectedValues map[string]string
	}{
		{
			name: "Valid principal line with standard user",
			lines: []string{
				"Ticket cache: FILE:/path/to/krb5cc",
				"Default principal: user123@EXAMPLE.COM",
			},
			expectedError: false,
			expectedValues: map[string]string{
				"principal":      "user123",
				"domain":         "EXAMPLE.COM",
				"domainlessUser": "user123",
			},
		},
		{
			name: "Valid principal line with machine account",
			lines: []string{
				"Ticket cache: FILE:/path/to/krb5cc",
				"Default principal: machine$@EXAMPLE.COM",
			},
			expectedError: false,
			expectedValues: map[string]string{
				"principal":      "machine$",
				"domain":         "EXAMPLE.COM",
				"domainlessUser": "machine",
			},
		},
		{
			name: "Missing principal line",
			lines: []string{
				"Ticket cache: FILE:/path/to/krb5cc",
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ticket := &types.Ticket{}
			ticketInfo := &types.TicketInfo{}

			err := parsePrincipalInfo(tc.lines, ticket, ticketInfo)

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.Equal(t, tc.expectedValues["principal"], ticket.Principal, "Principal doesn't match expected")
				assert.Equal(t, tc.expectedValues["domain"], ticket.Domain, "Domain doesn't match expected")
				assert.Equal(t, tc.expectedValues["domainlessUser"], ticketInfo.DomainlessUser, "DomainlessUser doesn't match expected")
			}
		})
	}
}

func TestDateParsing(t *testing.T) {
	t.Run("parseTicketLine", func(t *testing.T) {
		ticket := &types.Ticket{}
		parseTicketLine("05/15/2023 09:00:00 05/16/2023 10:00:00", ticket)
		assert.Equal(t, parseTime("05/15/2023 09:00:00"), ticket.CreationTime)
		assert.Equal(t, parseTime("05/16/2023 10:00:00"), ticket.ExpirationTime)
	})

	t.Run("parseStartTime", func(t *testing.T) {
		ticket := &types.Ticket{}
		parseStartTime("05/15/2023 09:00:00", ticket)
		assert.Equal(t, parseTime("05/15/2023 09:00:00"), ticket.CreationTime)
	})

	t.Run("parseExpiryTime", func(t *testing.T) {
		ticket := &types.Ticket{}
		parseExpiryTime("05/16/2023 10:00:00", ticket)
		assert.Equal(t, parseTime("05/16/2023 10:00:00"), ticket.ExpirationTime)
	})

	t.Run("parseRenewTime", func(t *testing.T) {
		ticket := &types.Ticket{}
		parseRenewTime("renew until 05/22/2023 09:00:00", ticket)
		assert.Equal(t, parseTime("05/22/2023 09:00:00"), ticket.RenewUntil)
	})
}

func TestIsDateFormat(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected bool
	}{
		{
			name:     "05/15/2023",
			input:    "05/15/2023",
			expected: true,
		},
		{
			name:     "12/31/2023",
			input:    "12/31/2023",
			expected: true,
		},
		{
			name:     "5/15/2023",
			input:    "5/15/2023",
			expected: false, // Missing leading zero
		},
		{
			name:     "05-15-2023",
			input:    "05-15-2023",
			expected: false, // Wrong separator
		},
		{
			name:     "05/15/23",
			input:    "05/15/23",
			expected: false, // Short year
		},
		{
			name:     "05/15/20233",
			input:    "05/15/20233",
			expected: false, // Too long
		},
		{
			name:     "hello",
			input:    "hello",
			expected: false, // Not a date
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := isDateFormat(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateTicket(t *testing.T) {
	testCases := []struct {
		name          string
		ticket        *types.Ticket
		expectedError bool
	}{
		{
			name: "Valid ticket",
			ticket: &types.Ticket{
				Path:           "/path/to/ticket",
				Principal:      "user123",
				Domain:         "EXAMPLE.COM",
				CreationTime:   parseTime("05/15/2023 09:00:00"),
				ExpirationTime: parseTime("05/16/2023 10:00:00"),
			},
			expectedError: false,
		},
		{
			name: "Missing principal",
			ticket: &types.Ticket{
				Path:           "/path/to/ticket",
				Domain:         "EXAMPLE.COM",
				CreationTime:   parseTime("05/15/2023 09:00:00"),
				ExpirationTime: parseTime("05/16/2023 10:00:00"),
			},
			expectedError: true,
		},
		{
			name: "Missing domain",
			ticket: &types.Ticket{
				Path:           "/path/to/ticket",
				Principal:      "user123",
				CreationTime:   parseTime("05/15/2023 09:00:00"),
				ExpirationTime: parseTime("05/16/2023 10:00:00"),
			},
			expectedError: true,
		},
		{
			name: "Missing expiration time",
			ticket: &types.Ticket{
				Path:         "/path/to/ticket",
				Principal:    "user123",
				Domain:       "EXAMPLE.COM",
				CreationTime: parseTime("05/15/2023 09:00:00"),
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateTicket(tc.ticket, "/path/to/ticket")

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}
		})
	}
}

// Helper function to parse time strings
func parseTime(timeStr string) time.Time {
	t, _ := time.Parse(constants.KlistDateTimeFormat, timeStr)
	return t
}
