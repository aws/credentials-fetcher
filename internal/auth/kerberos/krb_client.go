package kerberos

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

var (
	log = logger.New()
)

// Client handles Kerberos ticket operations
type Client struct{}

// NewClient creates a new Kerberos client
func NewClient() *Client {
	return &Client{}
}

// GetTicketInfo retrieves information about a Kerberos ticket from a file
func (c *Client) GetTicketInfo(path string) (*TicketInfo, error) {
	if !filepath.IsAbs(path) {
		log.Error("Invalid path", "path", path)
		return nil, fmt.Errorf("path must be absolute: %s", path)
	}

	if _, err := os.Stat(path); err != nil {
		log.Error("Failed to stat file", "path", path, "error", err)
		return nil, fmt.Errorf("failed to stat file: %w", err)
	}

	log.Debug("Reading ticket info", "path", path)
	cmd := exec.Command(InstallPathForDecodeExe, path)
	output, err := cmd.Output()
	if err != nil {
		log.Error("Failed to execute decode command", "error", err)
		return nil, fmt.Errorf("failed to execute decode command: %w", err)
	}

	var ticketInfo TicketInfo
	if err := json.Unmarshal(output, &ticketInfo); err != nil {
		log.Error("Failed to parse ticket info", "error", err)
		return nil, fmt.Errorf("failed to parse ticket info: %w", err)
	}

	log.Info("Successfully retrieved ticket info",
		"path", path,
		"service_account", ticketInfo.ServiceAccountName,
		"domain", ticketInfo.DomainName)

	return &ticketInfo, nil
}

// GetTicket retrieves a Kerberos ticket from a file
func (c *Client) GetTicketFromCache(path string) (*Ticket, error) {
	ticketInfo, err := c.GetTicketInfo(path)
	if err != nil {
		return nil, err
	}

	// Get ticket details using klist
	cmd := exec.Command("klist", "f", path)
	output, err := cmd.Output()
	if err != nil {
		log.Error("Failed to execute klist command", "error", err)
		return nil, fmt.Errorf("failed to execute klist command: %w", err)
	}

	// Parse klist output
	lines := strings.Split(string(output), "\n")
	ticket := &Ticket{
		Path:      path,
		Principal: ticketInfo.ServiceAccountName,
		Domain:    ticketInfo.DomainName,
	}

	for _, line := range lines {
		if strings.Contains(line, "Valid starting") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				startTime, err := time.Parse("01/02/2006 15:04:05", fields[2]+" "+fields[3])
				if err != nil {
					log.Warn("Failed to parse start time", "value", fields[2]+" "+fields[3], "error", err)
				} else {
					ticket.CreationTime = startTime
				}
			}
		} else if strings.Contains(line, "Expires") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				expiryTime, err := time.Parse("01/02/2006 15:04:05", fields[2]+" "+fields[3])
				if err != nil {
					log.Warn("Failed to parse expiry time", "value", fields[2]+" "+fields[3], "error", err)
				} else {
					ticket.ExpirationTime = expiryTime
				}
			}
		} else if strings.Contains(line, "Renew until") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				renewTime, err := time.Parse("01/02/2006 15:04:05", fields[2]+" "+fields[3])
				if err != nil {
					log.Warn("Failed to parse renew time", "value", fields[2]+" "+fields[3], "error", err)
				} else {
					ticket.RenewUntil = renewTime
				}
			}
		} else if strings.Contains(line, "Flags:") {
			flags := strings.TrimPrefix(line, "Flags: ")
			ticket.Flags = strings.Fields(flags)
		}
	}

	// Validate required fields
	if ticket.ExpirationTime.IsZero() {
		log.Error("Failed to parse expiry time from klist output", "path", path)
		return nil, fmt.Errorf("failed to parse expiry time from klist output for %s", path)
	}

	log.Info("Successfully retrieved ticket",
		"path", path,
		"principal", ticket.Principal,
		"expires", ticket.ExpirationTime.Format(time.RFC3339))

	return ticket, nil
}
