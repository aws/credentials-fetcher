package kerberos

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
	"golang.a2z.com/CredentialsFetcherV2/internal/shell"
)

var (
	log = logger.New()
)

var (
	readMetadataJSONFunc     = ReadMetadataJSON
	getMetadataFilePathsFunc = GetMetadataFilePaths
)

type Client struct{}

func NewClient() *Client {
	return &Client{}
}

type KlistExecutor interface {
	executeKlist(path string) (string, error)
}

type DefaultKlistExecutor struct {
	shellExecutor shell.Executor
}

func NewDefaultKlistExecutor() *DefaultKlistExecutor {
	return &DefaultKlistExecutor{
		shellExecutor: shell.NewExecutor(),
	}
}

var defaultExecutor KlistExecutor = NewDefaultKlistExecutor()

// executeKlist runs the klist command on the specified ticket file and returns the output
func (e *DefaultKlistExecutor) executeKlist(path string) (string, error) {
	ctx := context.Background()

	cmdString := e.shellExecutor.BuildCommand("klist", "-c", path)
	log.Debug("Executing klist command", "command", cmdString)

	output, err := e.shellExecutor.Execute(ctx, cmdString)
	if err != nil {
		log.Error("Klist command failed",
			"error", err,
			"output", string(output),
			"path", path)
		return "", fmt.Errorf("failed to execute klist command: %w", err)
	}
	log.Debug("Klist command completed successfully", "output_size", len(output))

	return string(output), nil
}

// parseKlistOutput parses the output of klist command to populate both Ticket and TicketInfo structs
func parseKlistOutput(output string, path string) (*Ticket, *TicketInfo, error) {
	lines := strings.Split(output, "\n")

	ticketInfo := &TicketInfo{
		KrbFilePath: path,
	}

	ticket := &Ticket{
		Path: path,
	}

	if err := parsePrincipalInfo(lines, ticket, ticketInfo); err != nil {
		return nil, nil, err
	}

	parseTicketDates(lines, ticket)

	if err := validateTicket(ticket, path); err != nil {
		return nil, nil, err
	}

	return ticket, ticketInfo, nil
}

// parsePrincipalInfo extracts principal and domain information from klist output
func parsePrincipalInfo(lines []string, ticket *Ticket, ticketInfo *TicketInfo) error {
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

func parseTicketDates(lines []string, ticket *Ticket) {
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
				parseTicketLine(ticketLine, ticket)
			}
			continue
		}

		// For multi-line format
		if inTicketSection {
			// Check if line starts with a date
			if dateStartRegex.MatchString(line) {
				parseStartTime(line, ticket)
			} else if strings.Contains(line, "renew until") {
				parseRenewTime(line, ticket)
			} else if ticket.CreationTime.IsZero() && !ticket.ExpirationTime.IsZero() {
				// If we have expiry but no creation time, this might be a multi-line format
				// with creation time missing, use a reasonable default
				ticket.CreationTime = time.Now()
			} else if !strings.Contains(line, "Valid starting") &&
				!strings.Contains(line, "Service principal") &&
				len(strings.TrimSpace(line)) > 0 {
				parseExpiryTime(line, ticket)
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

// parseTicketLine handles the case where all ticket info is on one line
func parseTicketLine(line string, ticket *Ticket) {
	fields := strings.Fields(line)
	if len(fields) >= 4 {
		// First date (fields 0-1) is start time
		startTime, err := time.Parse("01/02/2006 15:04:05", fields[0]+" "+fields[1])
		if err != nil {
			log.Warn("Failed to parse start time from ticket line",
				"value", fields[0]+" "+fields[1], "error", err)
		} else {
			ticket.CreationTime = startTime
		}

		// Second date (fields 2-3) is expiry time
		expiryTime, err := time.Parse("01/02/2006 15:04:05", fields[2]+" "+fields[3])
		if err != nil {
			log.Warn("Failed to parse expiry time from ticket line",
				"value", fields[2]+" "+fields[3], "error", err)
		} else {
			ticket.ExpirationTime = expiryTime
		}
	}
}

// parseDateFromFields is a helper function to parse dates from fields with appropriate logging
func parseDateFromFields(fields []string, logPrefix string) (time.Time, error) {
	// Try to find date in the format MM/DD/YYYY
	for i, field := range fields {
		if i+1 < len(fields) && isDateFormat(field) {
			dateStr := field + " " + fields[i+1]
			parsedTime, err := time.Parse("01/02/2006 15:04:05", dateStr)
			if err != nil {
				log.Warn(fmt.Sprintf("Failed to parse %s time", logPrefix),
					"value", dateStr, "error", err)
				continue
			}
			return parsedTime, nil
		}
	}

	// Fallback: try brute force approach
	if len(fields) >= 4 && isDateFormat(fields[2]) {
		dateStr := fields[2] + " " + fields[3]
		parsedTime, err := time.Parse("01/02/2006 15:04:05", dateStr)
		if err != nil {
			log.Warn(fmt.Sprintf("Failed to parse %s time with fallback", logPrefix),
				"value", dateStr, "error", err)
			return time.Time{}, err
		}
		return parsedTime, nil
	}

	return time.Time{}, fmt.Errorf("could not parse date")
}

// parseStartTime extracts and sets the ticket creation time
func parseStartTime(line string, ticket *Ticket) {
	fields := strings.Fields(strings.TrimSpace(line))
	if parsedTime, err := parseDateFromFields(fields, "start"); err == nil {
		ticket.CreationTime = parsedTime
	}
}

// parseExpiryTime extracts and sets the ticket expiration time
func parseExpiryTime(line string, ticket *Ticket) {
	fields := strings.Fields(strings.TrimSpace(line))
	if parsedTime, err := parseDateFromFields(fields, "expiry"); err == nil {
		ticket.ExpirationTime = parsedTime
	}
}

// parseRenewTime extracts and sets the ticket renewal time
func parseRenewTime(line string, ticket *Ticket) {
	fields := strings.Fields(strings.TrimSpace(line))
	if parsedTime, err := parseDateFromFields(fields, "renew"); err == nil {
		ticket.RenewUntil = parsedTime
	}
}

// Helper function to check if a string is in date format MM/DD/YYYY
func isDateFormat(str string) bool {
	return len(str) == 10 &&
		str[2] == '/' &&
		str[5] == '/' &&
		(str[0] >= '0' && str[0] <= '1') &&
		(str[3] >= '0' && str[3] <= '3')
}

// validateTicket ensures the ticket has all required fields
func validateTicket(ticket *Ticket, path string) error {
	if ticket.Principal == "" || ticket.Domain == "" {
		return fmt.Errorf("could not find principal information in klist output")
	}

	if ticket.ExpirationTime.IsZero() {
		return fmt.Errorf("failed to parse expiry time from klist output for %s", path)
	}

	return nil
}

// GetTicket retrieves comprehensive information about a Kerberos ticket from a file
func (c *Client) GetTicket(path string, executor KlistExecutor) (*Ticket, *TicketInfo, error) {
	log.Debug("Reading ticket info using klist", "path", path)

	// If no executor is provided, use the default one
	if executor == nil {
		executor = defaultExecutor
	}

	output, err := executor.executeKlist(path)
	if err != nil {
		log.Error("Failed to execute klist command", "error", err)
		return nil, nil, fmt.Errorf("failed to execute klist command: %w", err)
	}

	ticket, ticketInfo, err := parseKlistOutput(output, path)
	if err != nil {
		log.Error("Failed to parse klist output", "error", err)
		return nil, nil, fmt.Errorf("failed to parse klist output: %w", err)
	}

	log.Info("Successfully retrieved ticket",
		"path", path,
		"principal", ticket.Principal,
		"expires", ticket.ExpirationTime.Format(time.RFC3339))

	return ticket, ticketInfo, nil
}

// GetTicketsFromMetadata retrieves all ticket information from a metadata file
func (c *Client) GetTicketsFromMetadata(metadataPath string) ([]*Ticket, []*TicketInfo, error) {

	ticketInfoList, err := readMetadataJSONFunc(metadataPath)
	if err != nil {
		log.Error("Failed to read metadata file", "path", metadataPath, "error", err)
		return nil, nil, fmt.Errorf("failed to read metadata file: %w", err)
	}

	if len(ticketInfoList) == 0 {
		log.Error("No ticket information found in metadata file", "path", metadataPath)
		return nil, nil, fmt.Errorf("no ticket information found in metadata file: %s", metadataPath)
	}

	var tickets []*Ticket
	var validTicketInfos []*TicketInfo

	for _, ticketInfo := range ticketInfoList {
		ticket, _, err := c.GetTicket(ticketInfo.KrbFilePath, defaultExecutor)
		if err != nil {
			log.Warn("Failed to get ticket referenced in metadata",
				"metadata_path", metadataPath,
				"ticket_path", ticketInfo.KrbFilePath,
				"error", err)
			continue // Skip this ticket and try the next one
		}

		tickets = append(tickets, ticket)
		validTicketInfos = append(validTicketInfos, ticketInfo)
	}

	if len(tickets) == 0 {
		log.Error("No valid tickets found in metadata file", "path", metadataPath)
		return nil, nil, fmt.Errorf("no valid tickets found in metadata file: %s", metadataPath)
	}

	return tickets, validTicketInfos, nil
}

// GetAllTicketsFromDirectory retrieves all tickets from metadata files in a directory
func (c *Client) GetAllTicketsFromDirectory(directory string) ([]*Ticket, []*TicketInfo, error) {

	metadataFiles, err := getMetadataFilePathsFunc(directory)
	if err != nil {
		log.Error("Failed to get metadata files", "directory", directory, "error", err)
		return nil, nil, fmt.Errorf("failed to get metadata files: %w", err)
	}

	var allTickets []*Ticket
	var allTicketInfos []*TicketInfo

	for _, metadataPath := range metadataFiles {
		tickets, ticketInfos, err := c.GetTicketsFromMetadata(metadataPath)
		if err != nil {
			log.Warn("Failed to get tickets from metadata", "path", metadataPath, "error", err)
			continue // Skip this file and continue with others
		}

		allTickets = append(allTickets, tickets...)
		allTicketInfos = append(allTicketInfos, ticketInfos...)
	}

	if len(allTickets) == 0 {
		log.Error("No valid tickets found in directory", "directory", directory)
		return nil, nil, fmt.Errorf("no valid tickets found in directory: %s", directory)
	}

	return allTickets, allTicketInfos, nil
}
