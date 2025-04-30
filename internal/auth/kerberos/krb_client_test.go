package kerberos

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.a2z.com/CredentialsFetcherV2/constants"
)

// MockKlistExecutor mocks the KlistExecutor interface for testing
type MockKlistExecutor struct {
	Output string
	Err    error
}

func (m *MockKlistExecutor) executeKlist(path string) (string, error) {
	return m.Output, m.Err
}

// Valid klist output formats for testing
const (
	// Format with all dates on one line
	validKlistCompactOutput = `Ticket cache: FILE:/path/to/krb5cc
Default principal: user123@EXAMPLE.COM

Valid starting     Expires            Service principal
05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM`

	// Format with dates on separate lines
	validKlistMultilineOutput = `Ticket cache: FILE:/path/to/krb5cc
Default principal: user123@EXAMPLE.COM

Valid starting       Expires              Service principal
05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
	renew until 05/22/2023 10:00:00`

	// Format with machine account
	validKlistMachineOutput = `Ticket cache: FILE:/path/to/krb5cc
Default principal: machine$@EXAMPLE.COM

Valid starting     Expires            Service principal
05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM`
)

func TestGetTicket(t *testing.T) {
	testCases := []struct {
		name          string
		klistOutput   string
		klistErr      error
		expectedError bool
	}{
		{
			name:          "Valid ticket (compact format)",
			klistOutput:   validKlistCompactOutput,
			klistErr:      nil,
			expectedError: false,
		},
		{
			name:          "Valid ticket (multiline format)",
			klistOutput:   validKlistMultilineOutput,
			klistErr:      nil,
			expectedError: false,
		},
		{
			name:          "Klist command failure",
			klistOutput:   "",
			klistErr:      errors.New("klist command failed"),
			expectedError: true,
		},
		{
			name: "Missing principal",
			klistOutput: `Ticket cache: FILE:/path/to/krb5cc

Valid starting     Expires            Service principal
05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM`,
			klistErr:      nil,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mockExecutor := &MockKlistExecutor{
				Output: tc.klistOutput,
				Err:    tc.klistErr,
			}

			client := NewClient()
			ticket, ticketInfo, err := client.GetTicket("/path/to/ticket", mockExecutor)

			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
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
		mockTicketInfos     []*TicketInfo
		mockReadErr         error
		mockKlistOutput     string
		mockKlistErr        error
		expectedTicketCount int
		expectedError       bool
	}{
		{
			name: "Valid metadata with ticket",
			mockTicketInfos: []*TicketInfo{
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
			mockTicketInfos:     []*TicketInfo{},
			mockReadErr:         nil,
			mockKlistOutput:     "",
			mockKlistErr:        nil,
			expectedTicketCount: 0,
			expectedError:       true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Save original functions
			originalReadFunc := readMetadataJSONFunc
			originalExecutor := defaultExecutor

			// Restore them after test
			defer func() {
				readMetadataJSONFunc = originalReadFunc
				defaultExecutor = originalExecutor
			}()

			// Set up mock functions
			readMetadataJSONFunc = func(filePath string) ([]*TicketInfo, error) {
				return tc.mockTicketInfos, tc.mockReadErr
			}

			// Create a mock executor and replace the default one
			defaultExecutor = &MockKlistExecutor{
				Output: tc.mockKlistOutput,
				Err:    tc.mockKlistErr,
			}

			client := NewClient()
			tickets, infos, err := client.GetTicketsFromMetadata("/path/to/metadata.json")

			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(tickets) != tc.expectedTicketCount {
					t.Errorf("Expected %d tickets but got %d", tc.expectedTicketCount, len(tickets))
				}
				if len(infos) != tc.expectedTicketCount {
					t.Errorf("Expected %d ticket infos but got %d", tc.expectedTicketCount, len(infos))
				}
			}
		})
	}
}

func TestGetAllTicketsFromDirectory(t *testing.T) {
	testCases := []struct {
		name                string
		mockMetadataFiles   []string
		mockGetPathsErr     error
		mockTicketInfos     []*TicketInfo
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
			mockTicketInfos: []*TicketInfo{
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
			// Save original functions
			originalReadFunc := readMetadataJSONFunc
			originalGetPathsFunc := getMetadataFilePathsFunc
			originalExecutor := defaultExecutor

			// Restore them after test
			defer func() {
				readMetadataJSONFunc = originalReadFunc
				getMetadataFilePathsFunc = originalGetPathsFunc
				defaultExecutor = originalExecutor
			}()

			// Set up mock functions
			getMetadataFilePathsFunc = func(directory string) ([]string, error) {
				return tc.mockMetadataFiles, tc.mockGetPathsErr
			}

			readMetadataJSONFunc = func(filePath string) ([]*TicketInfo, error) {
				return tc.mockTicketInfos, tc.mockReadErr
			}

			// Create a mock executor and replace the default one
			defaultExecutor = &MockKlistExecutor{
				Output: tc.mockKlistOutput,
				Err:    tc.mockKlistErr,
			}

			client := NewClient()
			tickets, infos, err := client.GetAllTicketsFromDirectory("/path/to/directory")

			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if len(tickets) != tc.expectedTicketCount {
					t.Errorf("Expected %d tickets but got %d", tc.expectedTicketCount, len(tickets))
				}
				if len(infos) != tc.expectedTicketCount {
					t.Errorf("Expected %d ticket infos but got %d", tc.expectedTicketCount, len(infos))
				}
			}
		})
	}
}

func TestParseKlistOutput(t *testing.T) {
	testCases := []struct {
		name           string
		klistOutput    string
		path           string
		expectedError  bool
		expectedValues map[string]string
	}{
		{
			name:          "Valid output with standard principal",
			klistOutput:   validKlistCompactOutput,
			path:          "/path/to/ticket",
			expectedError: false,
			expectedValues: map[string]string{
				"principal":      "user123",
				"domain":         "EXAMPLE.COM",
				"domainlessUser": "user123",
			},
		},
		{
			name:          "Valid output with machine account",
			klistOutput:   validKlistMachineOutput,
			path:          "/path/to/ticket",
			expectedError: false,
			expectedValues: map[string]string{
				"principal":      "machine$",
				"domain":         "EXAMPLE.COM",
				"domainlessUser": "machine",
			},
		},
		{
			name: "Missing principal",
			klistOutput: `Ticket cache: FILE:/path/to/krb5cc

Valid starting     Expires            Service principal
05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM`,
			path:          "/path/to/ticket",
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ticket, ticketInfo, err := parseKlistOutput(tc.klistOutput, tc.path)

			if tc.expectedError {
				if err == nil {
					t.Errorf("Expected error but got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if ticket.Principal != tc.expectedValues["principal"] {
				t.Errorf("Expected principal %s but got %s",
					tc.expectedValues["principal"], ticket.Principal)
			}

			if ticket.Domain != tc.expectedValues["domain"] {
				t.Errorf("Expected domain %s but got %s",
					tc.expectedValues["domain"], ticket.Domain)
			}

			if ticketInfo.DomainlessUser != tc.expectedValues["domainlessUser"] {
				t.Errorf("Expected domainless user %s but got %s",
					tc.expectedValues["domainlessUser"], ticketInfo.DomainlessUser)
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
			ticket := &Ticket{}
			ticketInfo := &TicketInfo{}

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
	ticket := &Ticket{}
	t.Run("parseTicketLine", func(t *testing.T) {
		parseTicketLine("05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM", ticket)
		expectedCreation, _ := time.Parse(constants.KlistDateTimeFormat, "05/15/2023 10:00:00")
		expectedExpiry, _ := time.Parse(constants.KlistDateTimeFormat, "05/16/2023 10:00:00")

		assert.Equal(t, expectedCreation, ticket.CreationTime, "Creation time doesn't match expected")
		assert.Equal(t, expectedExpiry, ticket.ExpirationTime, "Expiration time doesn't match expected")
	})
	t.Run("parseStartTime", func(t *testing.T) {
		ticket = &Ticket{} // Reset ticket
		parseStartTime("05/15/2023 10:00:00", ticket)
		expected, _ := time.Parse(constants.KlistDateTimeFormat, "05/15/2023 10:00:00")

		assert.Equal(t, expected, ticket.CreationTime, "Creation time doesn't match expected")
	})
	t.Run("parseExpiryTime", func(t *testing.T) {
		ticket = &Ticket{} // Reset ticket
		parseExpiryTime("05/16/2023 10:00:00", ticket)
		expected, _ := time.Parse(constants.KlistDateTimeFormat, "05/16/2023 10:00:00")

		assert.Equal(t, expected, ticket.ExpirationTime, "Expiration time doesn't match expected")
	})

	t.Run("parseRenewTime", func(t *testing.T) {
		ticket = &Ticket{} // Reset ticket
		parseRenewTime("renew until 05/22/2023 10:00:00", ticket)
		expected, _ := time.Parse(constants.KlistDateTimeFormat, "05/22/2023 10:00:00")

		assert.Equal(t, expected, ticket.RenewUntil, "Renew time doesn't match expected")
	})
}

func TestIsDateFormat(t *testing.T) {
	testCases := []struct {
		input    string
		expected bool
	}{
		{"05/15/2023", true},
		{"12/31/2023", true},
		{"5/15/2023", false},   // missing leading zero
		{"05-15-2023", false},  // wrong separator
		{"05/15/23", false},    // year too short
		{"05/15/20233", false}, // year too long
		{"hello", false},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := isDateFormat(tc.input)
			assert.Equal(t, tc.expected, result, "isDateFormat(%s) should return %v", tc.input, tc.expected)
		})
	}
}

func TestValidateTicket(t *testing.T) {
	validTime := time.Now()

	testCases := []struct {
		name          string
		ticket        *Ticket
		expectedError bool
	}{
		{
			name: "Valid ticket",
			ticket: &Ticket{
				Principal:      "user123",
				Domain:         "EXAMPLE.COM",
				ExpirationTime: validTime,
			},
			expectedError: false,
		},
		{
			name: "Missing principal",
			ticket: &Ticket{
				Domain:         "EXAMPLE.COM",
				ExpirationTime: validTime,
			},
			expectedError: true,
		},
		{
			name: "Missing domain",
			ticket: &Ticket{
				Principal:      "user123",
				ExpirationTime: validTime,
			},
			expectedError: true,
		},
		{
			name: "Missing expiration time",
			ticket: &Ticket{
				Principal: "user123",
				Domain:    "EXAMPLE.COM",
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
