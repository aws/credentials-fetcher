package kerberos

import (
	"context"
	"fmt"
	"os"
	"strings"
)

// GenerateKrbTicketFromMachineKeytab generates a Kerberos ticket using the machine's keytab file
func (c *Client) GenerateKrbTicketFromMachineKeytab(ctx context.Context, domain string) error {
	log.Info("Generating Kerberos ticket from machine keytab", "domain", domain)

	// 1. Validate required commands are present
	if err := c.validateRequiredCommands(ctx); err != nil {
		return err
	}

	// 2. Get machine principal
	machinePrincipal, err := c.getMachinePrincipal(ctx, domain)
	if err != nil {
		log.Error("Failed to get machine principal", "error", err)
		return fmt.Errorf("failed to get machine principal: %w", err)
	}

	// 3. Execute kinit with machine keytab
	err = c.executeKinitWithMachineKeytab(ctx, machinePrincipal)
	if err != nil {
		log.Error("Failed to execute kinit with machine keytab",
			"principal", machinePrincipal,
			"error", err)
		return fmt.Errorf("failed to execute kinit with machine keytab: %w", err)
	}

	log.Info("Successfully generated Kerberos ticket from machine keytab",
		"domain", domain,
		"principal", machinePrincipal)
	return nil
}

// validateRequiredCommands checks if all required commands are present
func (c *Client) validateRequiredCommands(ctx context.Context) error {
	requiredCommands := []string{"realm", "kinit", "ldapsearch"}

	for _, cmd := range requiredCommands {
		_, err := c.shellExecutor.Execute(ctx, "which", cmd)
		if err != nil {
			log.Error("Required command not found", "command", cmd, "error", err)
			return fmt.Errorf("required command not found: %s: %w", cmd, err)
		}
	}

	return nil
}

// getMachinePrincipal gets the machine principal in the format 'HOSTNAME$@REALM'
func (c *Client) getMachinePrincipal(ctx context.Context, domain string) (string, error) {
	// Get hostname using Go's os.Hostname() instead of executing the hostname command
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}

	// Extract hostname without domain part
	if idx := strings.Index(hostname, "."); idx > 0 {
		hostname = hostname[:idx]
	}

	// Microsoft has a 15-character limit for hostnames in Active Directory
	const hostNameLengthLimit = 15
	if len(hostname) > hostNameLengthLimit {
		log.Warn("Hostname exceeds 15 characters, this can cause problems in getting Kerberos tickets",
			"hostname", hostname,
			"truncated_hostname", hostname[:hostNameLengthLimit])
		hostname = hostname[:hostNameLengthLimit]
	}

	// Try to get realm name from system, fallback to domain if not found
	realm, err := c.getRealmName(ctx)
	if err != nil {
		log.Warn("Failed to get realm name from system, using domain name instead",
			"domain", domain,
			"error", err)
		realm = strings.ToUpper(domain)
	}

	// Format: 'HOSTNAME$@REALM'
	principal := fmt.Sprintf("%s$@%s", hostname, realm)
	principal = strings.ToUpper(principal)

	log.Info("Generated machine principal", "principal", principal)
	return principal, nil
}

// getRealmName gets the realm name from the system
// This is a Go implementation of the C++ function from credentials-fetcher:
// https://github.com/aws/credentials-fetcher/blob/dc5c2caec5e78052327b39cf2528eea7b2f45c91/common/util.hpp#L113
func (c *Client) getRealmName(ctx context.Context) (string, error) {
	// First try using 'realm list' command
	output, err := c.shellExecutor.Execute(
		ctx,
		"bash",
		"-c",
		"realm list | grep 'realm-name' | cut -f2 -d: | tr -d ' ' | tr -d '\n'",
	)

	if err == nil && len(output) > 0 {
		realm := strings.TrimSpace(string(output))
		log.Info("Found realm name using 'realm list'", "realm", realm)
		return realm, nil
	}

	// If 'realm list' fails, try using 'net ads info'
	output, err = c.shellExecutor.Execute(
		ctx,
		"bash",
		"-c",
		"net ads info | grep 'Realm' | cut -f2 -d: | tr -d ' ' | tr -d '\n'",
	)

	if err == nil && len(output) > 0 {
		realm := strings.TrimSpace(string(output))
		log.Info("Found realm name using 'net ads info'", "realm", realm)
		return realm, nil
	}

	return "", fmt.Errorf("failed to get realm name from system")
}

// executeKinitWithMachineKeytab executes kinit with the machine keytab
func (c *Client) executeKinitWithMachineKeytab(ctx context.Context, principal string) error {
	// Check if keytab file exists
	keytabPath := "/etc/krb5.keytab"
	if _, err := os.Stat(keytabPath); os.IsNotExist(err) {
		return fmt.Errorf("machine keytab file not found at %s", keytabPath)
	}

	// Execute: kinit -kt /etc/krb5.keytab PRINCIPAL
	output, err := c.shellExecutor.Execute(
		ctx,
		"kinit",
		"-kt", keytabPath,
		principal,
	)

	if err != nil {
		log.Error("Kinit command failed",
			"error", err,
			"output", string(output),
			"principal", principal)
		return fmt.Errorf("failed to execute kinit command: %v: %s", err, string(output))
	}

	log.Info("Successfully executed kinit with machine keytab", "principal", principal)
	return nil
}
