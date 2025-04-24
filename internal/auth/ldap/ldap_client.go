package ldap

import (
	"context"
	"fmt"
	"os/exec"
	"strings"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

var log = logger.New()

// Client handles LDAP operations
type Client struct{}

// NewClient creates a new LDAP client
func NewClient() *Client {
	log.Info("Creating new LDAP client")
	return &Client{}
}

// SearchGMSAPassword searches for a gMSA account's password
func (c *Client) SearchGMSAPassword(ctx context.Context, dn, fqdn string) ([]byte, error) {
	log.Info("Searching for gMSA password",
		"dn", dn,
		"fqdn", fqdn)

	searchFilter := fmt.Sprintf("(&%s(distinguishedName=%s))", constants.LDAPSearchFilterString, dn)
	log.Debug("LDAP search filter", "filter", searchFilter)

	cmd := exec.CommandContext(ctx, "ldapsearch",
		"-Y", "GSSAPI",
		"-H", "ldap://"+fqdn,
		"-b", dn,
		"-s", "base",
		searchFilter, "-N",
		"msDS-ManagedPassword")

	log.Debug("Executing ldapsearch command",
		"command", cmd.String(),
		"args", cmd.Args)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("ldapsearch failed",
			"error", err,
			"output", string(output),
			"dn", dn,
			"fqdn", fqdn)
		return nil, fmt.Errorf("ldapsearch failed: %w: %s", err, string(output))
	}

	log.Debug("ldapsearch completed successfully",
		"output_size", len(output))

	// Parse the output to extract the password
	password, err := extractManagedPassword(output)
	if err != nil {
		log.Error("Failed to extract managed password",
			"error", err,
			"dn", dn)
		return nil, fmt.Errorf("failed to extract managed password: %w", err)
	}

	log.Info("Successfully retrieved gMSA password",
		"dn", dn,
		"password_size", len(password))

	return password, nil
}

// FindServiceAccountDN finds the Distinguished Name for a service account
func (c *Client) FindServiceAccountDN(ctx context.Context, account, baseDN, fqdn string) (string, error) {
	log.Info("Finding service account DN",
		"account", account,
		"base_dn", baseDN,
		"fqdn", fqdn)

	searchFilter := fmt.Sprintf("(&(objectClass=msDS-GroupManagedServiceAccount)(sAMAccountName=%s))", account)
	log.Debug("LDAP search filter", "filter", searchFilter)

	cmd := exec.CommandContext(ctx, "ldapsearch",
		"-Y", "GSSAPI",
		"-H", "ldap://"+fqdn,
		"-b", baseDN,
		"-s", "sub",
		searchFilter,
		"distinguishedName")

	log.Debug("Executing ldapsearch command",
		"command", cmd.String(),
		"args", cmd.Args)

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("ldapsearch failed",
			"error", err,
			"output", string(output),
			"account", account,
			"base_dn", baseDN,
			"fqdn", fqdn)
		return "", fmt.Errorf("ldapsearch failed: %w: %s", err, string(output))
	}

	log.Debug("ldapsearch completed successfully",
		"output_size", len(output),
		"output", string(output))

	// Parse output to find DN
	dn, err := extractDistinguishedName(string(output))
	if err != nil {
		log.Error("Failed to extract DN from LDAP response",
			"error", err,
			"account", account,
			"output", string(output))
		return "", fmt.Errorf("failed to extract DN: %w", err)
	}

	log.Info("Found service account DN",
		"account", account,
		"dn", dn,
		"fqdn", fqdn)

	return dn, nil
}

// GetBaseDN converts a domain name to a base DN
func (c *Client) GetBaseDN(domain string) string {
	log.Debug("Converting domain to base DN", "domain", domain)

	parts := strings.Split(domain, ".")
	var dn []string
	for _, part := range parts {
		dn = append(dn, "DC="+part)
	}
	baseDN := strings.Join(dn, ",")

	log.Debug("Converted domain to base DN",
		"domain", domain,
		"base_dn", baseDN)

	return baseDN
}

// extractDistinguishedName extracts the DN from ldapsearch output
func extractDistinguishedName(output string) (string, error) {
	log.Debug("Extracting DN from LDAP response",
		"output_size", len(output))

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "distinguishedName:") {
			dn := strings.TrimSpace(strings.TrimPrefix(line, "distinguishedName:"))
			log.Debug("Found DN in LDAP response", "dn", dn)
			return dn, nil
		}
	}

	log.Error("DN not found in LDAP response",
		"output", output)
	return "", fmt.Errorf("DN not found in LDAP response")
}

// extractManagedPassword extracts and decodes the msDS-ManagedPassword attribute
func extractManagedPassword(output []byte) ([]byte, error) {
	log.Debug("Extracting managed password from LDAP response",
		"output_size", len(output))

	// TODO: Implement proper MSDS-MANAGEDPASSWORD_BLOB parsing
	// Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e

	log.Debug("Using raw output as password until proper BLOB parsing is implemented")
	return output, nil
}
