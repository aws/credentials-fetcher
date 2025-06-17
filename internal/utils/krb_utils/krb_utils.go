package krb_utils

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/grpc_utils"
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/types"
)

var log = logger.GetInstance()

// ProcessCredentialSpecs processes credential specs and returns ticket info list
// If username is empty, it assumes domain-joined mode
func ProcessCredentialSpecs(credspecContents []string, username, leaseID string, krbFilesDir string) ([]*types.TicketInfo, error) {
	var ticketInfoList []*types.TicketInfo
	krbFilePathSet := make(map[string]bool) // Set to track unique Kerberos file paths

	for _, credspecContent := range credspecContents {
		// Parse the credential spec
		credSpec, err := grpc_utils.ParseCredSpec(credspecContent)
		if err != nil {
			log.Error("Failed to parse credential spec", "error", err)
			return nil, fmt.Errorf("failed to parse credential spec: %v", err)
		}

		// Create the Kerberos file path
		krbFilePath := filepath.Join(krbFilesDir, leaseID, credSpec.ServiceAccountName)

		log.Info("Created Kerberos file path for lease ID ", leaseID, " Service account ", credSpec.ServiceAccountName)

		// Create ticket info object and populate it with information from the credential spec
		ticketInfo := &types.TicketInfo{
			KrbFilePath:        krbFilePath,
			ServiceAccountName: credSpec.ServiceAccountName,
			DomainName:         credSpec.DomainName,
			DomainlessUser:     username, // Assumes domain-joined mode if username is "" (empty string)
			CredentialArn:      credSpec.CredentialArn,
		}

		// Handle duplicate service accounts
		if _, exists := krbFilePathSet[krbFilePath]; !exists {
			krbFilePathSet[krbFilePath] = true
			ticketInfoList = append(ticketInfoList, ticketInfo)
		} else {
			log.Info("Skipping duplicate service account", "path", krbFilePath)
		}
	}
	log.Info("Successfully parsed all supplied credspecs")

	return ticketInfoList, nil
}

// CleanupKerberosFiles removes the Kerberos files and the lease ID directory if service account directory is empty
func CleanupKerberosFiles(krbFilePath string) error {
	log.Info("Cleaning up Kerberos files", "path", krbFilePath)

	// First remove the krb5cc file
	if err := os.Remove(krbFilePath); err != nil && !os.IsNotExist(err) {
		log.Error("Failed to remove Kerberos file", "path", krbFilePath, "error", err)
		return fmt.Errorf("failed to remove Kerberos file: %v", err)
	}

	// Get the service account directory (parent of krb5cc file)
	serviceAccountDir := filepath.Dir(krbFilePath)

	// Check if service account directory exists and is empty
	if _, err := os.Stat(serviceAccountDir); err == nil {
		entries, err := os.ReadDir(serviceAccountDir)
		if err != nil {
			log.Warn("Failed to read service account directory", "path", serviceAccountDir, "error", err)
		} else if len(entries) == 0 {
			// Service account directory exists and is empty, remove it
			if err := os.Remove(serviceAccountDir); err != nil {
				log.Warn("Failed to remove empty service account directory", "path", serviceAccountDir, "error", err)
			} else {
				log.Info("Removed empty service account directory", "path", serviceAccountDir)

				// Get the lease ID directory (parent of service account directory)
				leaseDir := filepath.Dir(serviceAccountDir)

				// Remove the lease ID directory and all its contents
				if err := os.RemoveAll(leaseDir); err != nil {
					log.Warn("Failed to remove lease directory", "path", leaseDir, "error", err)
				} else {
					log.Info("Removed lease directory", "path", leaseDir)
				}
			}
		} else {
			log.Info("Service account directory is not empty, skipping removal", "path", serviceAccountDir)
		}
	} else if os.IsNotExist(err) {
		log.Info("Service account directory does not exist", "path", serviceAccountDir)
	} else {
		log.Warn("Failed to check service account directory", "path", serviceAccountDir, "error", err)
	}

	return nil
}

// ParseKlistOutput parses the output of klist command to populate both Ticket and TicketInfo structs
func ParseKlistOutput(output string, path string) (*types.Ticket, *types.TicketInfo, error) {
	lines := strings.Split(output, "\n")

	ticketInfo := &types.TicketInfo{
		KrbFilePath: path,
	}

	ticket := &types.Ticket{
		Path: path,
	}

	if err := ParsePrincipalInfo(lines, ticket, ticketInfo); err != nil {
		return nil, nil, err
	}

	ParseTicketDates(lines, ticket)

	if err := ValidateTicket(ticket, path); err != nil {
		return nil, nil, err
	}

	return ticket, ticketInfo, nil
}

// ParsePrincipalInfo extracts principal and domain information from klist output
func ParsePrincipalInfo(lines []string, ticket *types.Ticket, ticketInfo *types.TicketInfo) error {
	for _, line := range lines {
		if strings.Contains(line, "Default principal:") {
			// Format is typically: "Default principal: username@DOMAIN.COM"
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				principal := parts[2]
				principalParts := strings.Split(principal, "@")
				if len(principalParts) == 2 {

					serviceAccount := principalParts[0]

					serviceAccount = strings.Trim(serviceAccount, "'")

					ticketInfo.ServiceAccountName = serviceAccount
					ticketInfo.DomainName = principalParts[1]

					if strings.HasSuffix(serviceAccount, "$") {
						ticketInfo.DomainlessUser = serviceAccount[:len(serviceAccount)-1]
					} else {
						ticketInfo.DomainlessUser = serviceAccount
					}

					domainParts := strings.Split(ticketInfo.DomainName, ".")
					var dnParts []string
					for _, part := range domainParts {
						dnParts = append(dnParts, "DC="+part)
					}
					ticketInfo.DistinguishedName = "CN=" + serviceAccount + "," + strings.Join(dnParts, ",")

					ticket.Principal = serviceAccount
					ticket.Domain = ticketInfo.DomainName

					return nil
				}
			}
		}
	}

	return fmt.Errorf("could not find principal information in klist output")
}

// ParseTicketDates parses ticket dates from klist output
func ParseTicketDates(lines []string, ticket *types.Ticket) {
	inTicketSection := false
	var ticketLine string
	dateStartRegex := regexp.MustCompile(`^\s*(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])`)

	// Check both one-line and multi-line formats
	for i, line := range lines {
		if strings.Contains(line, "Valid starting") {
			inTicketSection = true
			// Try to find the whole ticket line (compact format)
			if i+1 < len(lines) && len(strings.TrimSpace(lines[i+1])) > 0 &&
				!strings.Contains(lines[i+1], "Renew until") {
				ticketLine = lines[i+1]
				ParseTicketLine(ticketLine, ticket)
			}
			continue
		}

		// For multi-line format
		if inTicketSection {
			// Check if line starts with a date
			if dateStartRegex.MatchString(line) {
				ParseStartTime(line, ticket)
			} else if strings.Contains(line, "renew until") {
				ParseRenewTime(line, ticket)
			} else if ticket.CreationTime.IsZero() && !ticket.ExpirationTime.IsZero() {
				// If we have expiry but no creation time, this might be a multi-line format
				// with creation time missing, use a reasonable default
				ticket.CreationTime = time.Now()
			} else if !strings.Contains(line, "Valid starting") &&
				!strings.Contains(line, "Service principal") &&
				len(strings.TrimSpace(line)) > 0 {
				ParseExpiryTime(line, ticket)
			}
		}
	}

	// Last resort if we still don't have both times
	if ticket.ExpirationTime.IsZero() && !ticket.CreationTime.IsZero() {
		// Default expiry to 24h after creation as a fallback
		ticket.ExpirationTime = ticket.CreationTime.Add(24 * time.Hour)
		log.Warn("Could not parse expiry time, setting default 24h expiry",
			"creation", ticket.CreationTime)
	}
}

// ParseTicketLine handles the case where all ticket info is on one line
func ParseTicketLine(line string, ticket *types.Ticket) {
	fields := strings.Fields(line)
	if len(fields) >= 4 {
		// First date (fields 0-1) is start time
		dateStr := fields[0] + " " + fields[1]

		// Try MM/DD/YY format first
		startTime, err := time.Parse(constants.KlistDateTimeFormat, dateStr)
		if err != nil {
			// If that fails, try MM/DD/YYYY format
			startTime, err = time.Parse(constants.KlistDateTimeFormatLong, dateStr)
			if err != nil {
				log.Warn("Failed to parse start time from ticket line - tried both MM/DD/YY and MM/DD/YYYY formats",
					"value", dateStr)
			} else {
				log.Info("Successfully parsed start time using MM/DD/YYYY format",
					"value", dateStr)
				ticket.CreationTime = startTime
			}
		} else {
			log.Info("Successfully parsed start time using MM/DD/YY format",
				"value", dateStr)
			ticket.CreationTime = startTime
		}

		// Second date (fields 2-3) is expiry time
		dateStr = fields[2] + " " + fields[3]

		// Try MM/DD/YY format first
		expiryTime, err := time.Parse(constants.KlistDateTimeFormat, dateStr)
		if err != nil {
			// If that fails, try MM/DD/YYYY format
			expiryTime, err = time.Parse(constants.KlistDateTimeFormatLong, dateStr)
			if err != nil {
				log.Warn("Failed to parse expiry time from ticket line - tried both MM/DD/YY and MM/DD/YYYY formats",
					"value", dateStr)
			} else {
				log.Info("Successfully parsed expiry time using MM/DD/YYYY format",
					"value", dateStr)
				ticket.ExpirationTime = expiryTime
			}
		} else {
			log.Info("Successfully parsed expiry time using MM/DD/YY format",
				"value", dateStr)
			ticket.ExpirationTime = expiryTime
		}
	}
}

// ParseDateFromFields is a helper function to parse dates from fields with appropriate logging
func ParseDateFromFields(fields []string, logPrefix string) (time.Time, error) {
	// Try to find date in the format MM/DD/YY or MM/DD/YYYY
	for i, field := range fields {
		if i+1 < len(fields) && IsDateFormat(field) {
			dateStr := field + " " + fields[i+1]

			// Try MM/DD/YY format first
			parsedTime, err := time.Parse(constants.KlistDateTimeFormat, dateStr)
			if err == nil {
				log.Info(fmt.Sprintf("Successfully parsed %s time using MM/DD/YY format", logPrefix),
					"value", dateStr)
				return parsedTime, nil
			}

			// If that fails, try MM/DD/YYYY format
			parsedTime, err = time.Parse(constants.KlistDateTimeFormatLong, dateStr)
			if err == nil {
				log.Info(fmt.Sprintf("Successfully parsed %s time using MM/DD/YYYY format", logPrefix),
					"value", dateStr)
				return parsedTime, nil
			}

			log.Warn(fmt.Sprintf("Failed to parse %s time - tried both MM/DD/YY and MM/DD/YYYY formats", logPrefix),
				"value", dateStr)
		}
	}

	// Fallback: try brute force approach
	if len(fields) >= 2 {
		dateStr := fields[0] + " " + fields[1]

		// Try MM/DD/YY format first
		parsedTime, err := time.Parse(constants.KlistDateTimeFormat, dateStr)
		if err == nil {
			log.Info(fmt.Sprintf("Successfully parsed %s time using MM/DD/YY format (fallback)", logPrefix),
				"value", dateStr)
			return parsedTime, nil
		}

		// If that fails, try MM/DD/YYYY format
		parsedTime, err = time.Parse(constants.KlistDateTimeFormatLong, dateStr)
		if err == nil {
			log.Info(fmt.Sprintf("Successfully parsed %s time using MM/DD/YYYY format (fallback)", logPrefix),
				"value", dateStr)
			return parsedTime, nil
		}

		log.Warn(fmt.Sprintf("Failed to parse %s time with fallback - tried both MM/DD/YY and MM/DD/YYYY formats", logPrefix),
			"value", dateStr)
	}

	return time.Time{}, fmt.Errorf("could not parse date")
}

// ParseStartTime extracts and sets the ticket creation time
func ParseStartTime(line string, ticket *types.Ticket) {
	fields := strings.Fields(strings.TrimSpace(line))
	if parsedTime, err := ParseDateFromFields(fields, "start"); err == nil {
		ticket.CreationTime = parsedTime
	}
}

// ParseExpiryTime extracts and sets the ticket expiration time
func ParseExpiryTime(line string, ticket *types.Ticket) {
	fields := strings.Fields(strings.TrimSpace(line))
	if parsedTime, err := ParseDateFromFields(fields, "expiry"); err == nil {
		ticket.ExpirationTime = parsedTime
	}
}

// ParseRenewTime extracts and sets the ticket renewal time
func ParseRenewTime(line string, ticket *types.Ticket) {
	// Remove "renew until" prefix if present
	line = strings.Replace(line, "renew until", "", 1)
	line = strings.TrimSpace(line)

	fields := strings.Fields(line)
	if len(fields) >= 2 {
		dateStr := fields[0] + " " + fields[1]

		// Try MM/DD/YY format first
		parsedTime, err := time.Parse(constants.KlistDateTimeFormat, dateStr)
		if err == nil {
			log.Info("Successfully parsed renew time using MM/DD/YY format", "value", dateStr)
			ticket.RenewUntil = parsedTime
			return
		}

		// If that fails, try MM/DD/YYYY format
		parsedTime, err = time.Parse(constants.KlistDateTimeFormatLong, dateStr)
		if err == nil {
			log.Info("Successfully parsed renew time using MM/DD/YYYY format", "value", dateStr)
			ticket.RenewUntil = parsedTime
			return
		}

		log.Warn("Failed to parse renew time - tried both MM/DD/YY and MM/DD/YYYY formats", "value", dateStr)
	}

	// Fallback to ParseDateFromFields
	fields = strings.Fields(strings.TrimSpace(line))
	if parsedTime, err := ParseDateFromFields(fields, "renew"); err == nil {
		ticket.RenewUntil = parsedTime
	}
}

// IsDateFormat checks if a string is in date format MM/DD/YY or MM/DD/YYYY
func IsDateFormat(str string) bool {
	// Check for MM/DD/YY format (8 chars)
	if len(str) == 8 &&
		str[2] == '/' &&
		str[5] == '/' &&
		(str[0] >= '0' && str[0] <= '1') &&
		(str[3] >= '0' && str[3] <= '3') {
		return true
	}

	// Check for MM/DD/YYYY format (10 chars)
	if len(str) == 10 &&
		str[2] == '/' &&
		str[5] == '/' &&
		(str[0] >= '0' && str[0] <= '1') &&
		(str[3] >= '0' && str[3] <= '3') {
		return true
	}

	return false
}

// ValidateTicket ensures the ticket has all required fields
func ValidateTicket(ticket *types.Ticket, path string) error {
	if ticket.Principal == "" || ticket.Domain == "" {
		return fmt.Errorf("could not find principal information in klist output")
	}

	if ticket.ExpirationTime.IsZero() {
		return fmt.Errorf("failed to parse expiry time from klist output for %s", path)
	}

	return nil
}

// IsTicketReadyForRenewal checks if a ticket is ready for renewal based on its expiration time
func IsTicketReadyForRenewal(ticket *types.Ticket) bool {
	// Calculate the time difference in hours
	now := time.Now()
	hours := ticket.ExpirationTime.Sub(now).Hours()

	// Check if the ticket needs to be renewed
	log.Info("Checking if ticket Expiration time is within the Renewal threshold")
	return hours <= float64(constants.KrbTicketRenewalThreshold)
}

// IsDomainlessUserWithSecret checks if a domainless user has AWS secret support
func IsDomainlessUserWithSecret(domainlessUser string) bool {
	return domainlessUser != "" &&
		(strings.Contains(domainlessUser, "awsdomainlessusersecret"))
}
