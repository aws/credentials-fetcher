package ldap

import (
	"context"
	"fmt"
	"os/exec"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

var log = logger.New()

type Client struct{}

func NewClient() *Client {
	log.Info("Creating new LDAP client")
	return &Client{}
}

type LdapsearchExecutor interface {
	executeLdapsearch(ctx context.Context, dn, fqdn string) ([]byte, error)
}

type DefaultLdapsearchExecutor struct{}

func (e *DefaultLdapsearchExecutor) executeLdapsearch(ctx context.Context, dn, fqdn string) ([]byte, error) {
	searchFilter := fmt.Sprintf("(&%s(distinguishedName=%s))", constants.LDAPSearchFilterString, dn)
	log.Debug("LDAP search filter", "filter", searchFilter)

	cmd := exec.CommandContext(ctx, constants.LDAPSearchBase+fqdn,
		"-b", dn,
		"-s", "sub",
		searchFilter,
		"msDS-ManagedPassword", "-N")

	log.Debug("Executing ldapsearch command",
		"command", cmd.String(),
		"args", cmd.Args)

	// ldapsearch command should look like :
	// ldapsearch -o ldif_wrap=no -LLL -Y GSSAPI -H ldap://ip-c613012f.contoso.com -b 'CN=WebApp01,OU=MYOU,OU=Users,OU=contoso,DC=contoso,DC=com'
	// -s sub  '(objectClass=msDs-GroupManagedServiceAccount)' msDS-ManagedPassword -N

	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Error("ldapsearch failed",
			"error", err,
			"output", string(output),
			"dn", dn,
			"fqdn", fqdn)
		return nil, fmt.Errorf("ldapsearch failed: %w: %s", err, string(output))
	}
	log.Debug("ldapsearch completed successfully", "output_size", len(output))

	return []byte(output), nil
}

// SearchGMSAPassword searches for a gMSA account's password
func (c *Client) SearchGMSAPassword(ctx context.Context, dn, fqdn string, executor LdapsearchExecutor) ([]byte, error) {
	log.Info("Searching for gMSA password",
		"dn", dn,
		"fqdn", fqdn)

	output, err := executor.executeLdapsearch(ctx, dn, fqdn)
	if err != nil {
		log.Error("Failed to execute ldapsearch command", "error", err)
		return nil, fmt.Errorf("failed to execute klist command: %w", err)
	}

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

// extractManagedPassword extracts and decodes the msDS-ManagedPassword attribute
func extractManagedPassword(output []byte) ([]byte, error) {
	log.Debug("Extracting managed password from LDAP response",
		"output_size", len(output))

	// TODO: Implement proper MSDS-MANAGEDPASSWORD_BLOB parsing
	// Reference: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e

	log.Debug("Using raw output as password until proper BLOB parsing is implemented")
	return output, nil
}
