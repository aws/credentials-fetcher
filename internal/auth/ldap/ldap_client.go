package ldap

import (
	"context"
	"fmt"

	"golang.a2z.com/CredentialsFetcherV2/constants"
	"golang.a2z.com/CredentialsFetcherV2/internal/cmdexec"
	"golang.a2z.com/CredentialsFetcherV2/internal/logger"
)

var log = logger.GetInstance()

type Client struct{}

func NewClient() *Client {
	log.Info("Creating new LDAP client")
	return &Client{}
}

type LdapsearchExecutor interface {
	executeLdapsearch(ctx context.Context, dn, fqdn string) ([]byte, error)
	buildLdapsearchCommand(dn, fqdn string) (string, []string)
}

type DefaultLdapsearchExecutor struct {
	shellExecutor cmdexec.Executor
}

func NewDefaultLdapsearchExecutor() *DefaultLdapsearchExecutor {
	return &DefaultLdapsearchExecutor{
		shellExecutor: cmdexec.NewExecutor(),
	}
}

// buildLdapsearchCommand creates the ldapsearch command and arguments
func (e *DefaultLdapsearchExecutor) buildLdapsearchCommand(dn, fqdn string) (string, []string) {
	searchFilter := fmt.Sprintf("(&%s(distinguishedName=%s))", constants.LDAPSearchFilterString, dn)
	log.Debug("LDAP search filter", "filter", searchFilter)

	command := constants.LDAPSearchBase + fqdn
	args := []string{
		"-b", dn,
		"-s", "sub",
		searchFilter,
		"msDS-ManagedPassword", "-N",
	}

	return command, args
}

func (e *DefaultLdapsearchExecutor) executeLdapsearch(ctx context.Context, dn, fqdn string) ([]byte, error) {

	command, args := e.buildLdapsearchCommand(dn, fqdn)

	cmdString := e.shellExecutor.BuildCommand(command, args...)
	log.Debug("Executing ldapsearch command", "command", cmdString)

	// ldapsearch command should look like :
	// ldapsearch -o ldif_wrap=no -LLL -Y GSSAPI -H ldap://ip-c613012f.contoso.com -b 'CN=WebApp01,OU=MYOU,OU=Users,OU=contoso,DC=contoso,DC=com'
	// -s sub  '(objectClass=msDs-GroupManagedServiceAccount)' msDS-ManagedPassword -N

	// Execute the command with separate command and arguments to prevent command injection
	output, err := e.shellExecutor.Execute(ctx, command, args...)
	if err != nil {
		log.Error("ldapsearch failed",
			"error", err,
			"output", string(output),
			"dn", dn,
			"fqdn", fqdn)
		return nil, fmt.Errorf("ldapsearch failed: %w: %s", err, string(output))
	}
	log.Debug("ldapsearch completed successfully", "output_size", len(output))

	return output, nil
}

// SearchGMSAPassword searches for a gMSA account's password
func (c *Client) SearchGMSAPassword(ctx context.Context, dn, fqdn string, executor LdapsearchExecutor) ([]byte, error) {
	log.Info("Searching for gMSA password",
		"dn", dn,
		"fqdn", fqdn)

	// If no executor is provided, create a default one
	if executor == nil {
		executor = NewDefaultLdapsearchExecutor()
	}

	output, err := executor.executeLdapsearch(ctx, dn, fqdn)
	if err != nil {
		log.Error("Failed to execute ldapsearch command", "error", err)
		return nil, fmt.Errorf("failed to execute ldapsearch command: %w", err)
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
