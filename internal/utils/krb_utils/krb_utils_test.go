package krb_utils

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

func TestParsePrincipalInfo(t *testing.T) {
	testCases := []struct {
		name          string
		lines         []string
		expectedError bool
	}{
		{
			name: "Valid principal line with standard user",
			lines: []string{
				"Ticket cache: FILE:/tmp/krb5cc_1000",
				"Default principal: user123@EXAMPLE.COM",
				"Valid starting       Expires              Service principal",
				"05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM",
			},
			expectedError: false,
		},
		{
			name: "Valid principal line with machine account",
			lines: []string{
				"Ticket cache: FILE:/tmp/krb5cc_1000",
				"Default principal: machine$@EXAMPLE.COM",
				"Valid starting       Expires              Service principal",
				"05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM",
			},
			expectedError: false,
		},
		{
			name: "Missing principal line",
			lines: []string{
				"Ticket cache: FILE:/tmp/krb5cc_1000",
				"Valid starting       Expires              Service principal",
				"05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM",
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ticket := &types.Ticket{}
			ticketInfo := &types.TicketInfo{}

			err := ParsePrincipalInfo(tc.lines, ticket, ticketInfo)

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.NotEmpty(t, ticket.Principal, "Expected principal to be set")
				assert.NotEmpty(t, ticket.Domain, "Expected domain to be set")
				assert.NotEmpty(t, ticketInfo.ServiceAccountName, "Expected service account name to be set")
				assert.NotEmpty(t, ticketInfo.DomainName, "Expected domain name to be set")
				assert.NotEmpty(t, ticketInfo.DomainlessUser, "Expected domainless user to be set")
				assert.NotEmpty(t, ticketInfo.DistinguishedName, "Expected distinguished name to be set")
			}
		})
	}
}

func TestDateParsing(t *testing.T) {
	t.Run("ParseTicketLine", func(t *testing.T) {
		ticket := &types.Ticket{}
		line := "05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM"

		ParseTicketLine(line, ticket)

		expectedCreationTime, _ := time.Parse(constants.KlistDateTimeFormat, "05/15/2023 10:00:00")
		expectedExpiryTime, _ := time.Parse(constants.KlistDateTimeFormat, "05/16/2023 10:00:00")

		assert.Equal(t, expectedCreationTime, ticket.CreationTime, "Creation time not parsed correctly")
		assert.Equal(t, expectedExpiryTime, ticket.ExpirationTime, "Expiry time not parsed correctly")
	})

	t.Run("ParseStartTime", func(t *testing.T) {
		ticket := &types.Ticket{}
		line := "05/15/2023 10:00:00"

		ParseStartTime(line, ticket)

		expectedTime, _ := time.Parse(constants.KlistDateTimeFormat, "05/15/2023 10:00:00")
		assert.Equal(t, expectedTime, ticket.CreationTime, "Start time not parsed correctly")
	})

	t.Run("ParseExpiryTime", func(t *testing.T) {
		ticket := &types.Ticket{}
		line := "05/16/2023 10:00:00"

		ParseExpiryTime(line, ticket)

		expectedTime, _ := time.Parse(constants.KlistDateTimeFormat, "05/16/2023 10:00:00")
		assert.Equal(t, expectedTime, ticket.ExpirationTime, "Expiry time not parsed correctly")
	})

	t.Run("ParseRenewTime", func(t *testing.T) {
		ticket := &types.Ticket{}
		line := "renew until 05/17/2023 10:00:00"

		ParseRenewTime(line, ticket)

		expectedTime, _ := time.Parse(constants.KlistDateTimeFormat, "05/17/2023 10:00:00")
		assert.Equal(t, expectedTime, ticket.RenewUntil, "Renew time not parsed correctly")
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
			expected: false, // Wrong year format
		},
		{
			name:     "05/15/20233",
			input:    "05/15/20233",
			expected: false, // Too many digits
		},
		{
			name:     "hello",
			input:    "hello",
			expected: false, // Not a date
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := IsDateFormat(tc.input)
			assert.Equal(t, tc.expected, result, "IsDateFormat returned unexpected result")
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
				Principal:      "user123",
				Domain:         "EXAMPLE.COM",
				CreationTime:   time.Now(),
				ExpirationTime: time.Now().Add(24 * time.Hour),
			},
			expectedError: false,
		},
		{
			name: "Missing principal",
			ticket: &types.Ticket{
				Domain:         "EXAMPLE.COM",
				CreationTime:   time.Now(),
				ExpirationTime: time.Now().Add(24 * time.Hour),
			},
			expectedError: true,
		},
		{
			name: "Missing domain",
			ticket: &types.Ticket{
				Principal:      "user123",
				CreationTime:   time.Now(),
				ExpirationTime: time.Now().Add(24 * time.Hour),
			},
			expectedError: true,
		},
		{
			name: "Missing expiration time",
			ticket: &types.Ticket{
				Principal:    "user123",
				Domain:       "EXAMPLE.COM",
				CreationTime: time.Now(),
			},
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateTicket(tc.ticket, "/path/to/ticket")

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
			}
		})
	}
}
func TestParseKlistOutput(t *testing.T) {
	testCases := []struct {
		name          string
		output        string
		path          string
		expectedError bool
	}{
		{
			name: "Valid klist output",
			output: `Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: user123@EXAMPLE.COM

Valid starting       Expires              Service principal
05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
`,
			path:          "/tmp/krb5cc_1000",
			expectedError: false,
		},
		{
			name: "Valid klist output with machine account",
			output: `Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: machine$@EXAMPLE.COM

Valid starting       Expires              Service principal
05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
`,
			path:          "/tmp/krb5cc_1000",
			expectedError: false,
		},
		{
			name: "Missing principal information",
			output: `Ticket cache: FILE:/tmp/krb5cc_1000

Valid starting       Expires              Service principal
05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM
`,
			path:          "/tmp/krb5cc_1000",
			expectedError: true,
		},
		{
			name: "Invalid date format",
			output: `Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: user123@EXAMPLE.COM

Valid starting       Expires              Service principal
invalid-date         invalid-date         krbtgt/EXAMPLE.COM@EXAMPLE.COM
`,
			path:          "/tmp/krb5cc_1000",
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ticket, ticketInfo, err := ParseKlistOutput(tc.output, tc.path)

			if tc.expectedError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Did not expect an error")
				assert.NotNil(t, ticket, "Expected ticket to be non-nil")
				assert.NotNil(t, ticketInfo, "Expected ticketInfo to be non-nil")
				assert.Equal(t, tc.path, ticket.Path, "Expected path to match")
				assert.Equal(t, tc.path, ticketInfo.KrbFilePath, "Expected KrbFilePath to match")
				assert.NotEmpty(t, ticket.Principal, "Expected principal to be set")
				assert.NotEmpty(t, ticket.Domain, "Expected domain to be set")
				assert.False(t, ticket.CreationTime.IsZero(), "Expected creation time to be set")
				assert.False(t, ticket.ExpirationTime.IsZero(), "Expected expiration time to be set")
			}
		})
	}
}
func TestParseTicketDates(t *testing.T) {
	testCases := []struct {
		name           string
		lines          []string
		expectCreation bool
		expectExpiry   bool
		expectRenew    bool
	}{
		{
			name: "Standard format with all dates",
			lines: []string{
				"Valid starting       Expires              Service principal",
				"05/15/2023 10:00:00  05/16/2023 10:00:00  krbtgt/EXAMPLE.COM@EXAMPLE.COM",
				"renew until 05/17/2023 10:00:00",
			},
			expectCreation: true,
			expectExpiry:   true,
			expectRenew:    true,
		},
		{
			name: "Multi-line format",
			lines: []string{
				"Valid starting",
				"05/15/2023 10:00:00",
				"Expires",
				"05/16/2023 10:00:00",
				"Service principal",
				"krbtgt/EXAMPLE.COM@EXAMPLE.COM",
				"renew until 05/17/2023 10:00:00",
			},
			expectCreation: true,
			expectExpiry:   true,
			expectRenew:    true,
		},
		{
			name: "Missing expiry time",
			lines: []string{
				"Valid starting       Expires              Service principal",
				"05/15/2023 10:00:00  invalid-date         krbtgt/EXAMPLE.COM@EXAMPLE.COM",
			},
			expectCreation: true,
			expectExpiry:   true, // Should set default expiry
			expectRenew:    false,
		},
		{
			name: "Empty lines",
			lines: []string{
				"",
				"",
			},
			expectCreation: false,
			expectExpiry:   false,
			expectRenew:    false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ticket := &types.Ticket{}

			ParseTicketDates(tc.lines, ticket)

			if tc.expectCreation {
				assert.False(t, ticket.CreationTime.IsZero(), "Expected creation time to be set")
			} else {
				assert.True(t, ticket.CreationTime.IsZero(), "Expected creation time to be zero")
			}

			if tc.expectExpiry {
				assert.False(t, ticket.ExpirationTime.IsZero(), "Expected expiration time to be set")
			} else {
				assert.True(t, ticket.ExpirationTime.IsZero(), "Expected expiration time to be zero")
			}

			if tc.expectRenew {
				assert.False(t, ticket.RenewUntil.IsZero(), "Expected renew time to be set")
			} else {
				assert.True(t, ticket.RenewUntil.IsZero(), "Expected renew time to be zero")
			}
		})
	}
}
