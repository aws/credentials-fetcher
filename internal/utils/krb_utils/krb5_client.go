package krb_utils

import (
	"fmt"
	"os"
	"strings"
)

// krb5Client implements Krb5Client using a Krb5Wrapper for all krb5 operations
type krb5Client struct {
	wrapper Krb5Wrapper
}

// NewKrb5Client creates a new Krb5Client with the given wrapper
func NewKrb5Client(wrapper Krb5Wrapper) Krb5Client {
	return &krb5Client{wrapper: wrapper}
}

// GenerateTicket generates a Kerberos ticket using the provided configuration
func (c *krb5Client) GenerateTicket(config *KinitConfig) error {
	// Handle renewal mode
	if config.RenewTicket {
		return c.renewTicket(config)
	}

	// Handle initial authentication
	return c.generateInitialTicket(config)
}

// renewTicket renews an existing Kerberos ticket (like kinit -R)
func (c *krb5Client) renewTicket(config *KinitConfig) error {
	// Validate required fields for renewal
	if config.CCachePath == "" {
		return fmt.Errorf("cache path is required for renewal")
	}

	// Initialize context
	ctx, err := c.wrapper.InitContext()
	if err != nil {
		return fmt.Errorf("failed to initialize krb5 context: %w", err)
	}
	defer c.wrapper.FreeContext(ctx)

	// Open existing credential cache
	cache, err := c.wrapper.ResolveCache(ctx, config.CCachePath)
	if err != nil {
		return fmt.Errorf("failed to resolve cache: %w", err)
	}
	defer c.wrapper.CloseCache(ctx, cache)

	// Get principal from cache
	princ, err := c.wrapper.GetPrincipal(ctx, cache)
	if err != nil {
		return fmt.Errorf("failed to get principal from cache: %w", err)
	}
	defer c.wrapper.FreePrincipal(ctx, princ)

	// Renew credentials
	creds, err := c.wrapper.GetRenewedCreds(ctx, cache, princ)
	if err != nil {
		return fmt.Errorf("failed to renew ticket: %w", err)
	}
	defer c.wrapper.FreeCredContents(ctx, creds)

	// Reinitialize and store renewed credentials
	if err := c.wrapper.InitializeCache(ctx, cache, princ); err != nil {
		return fmt.Errorf("failed to reinitialize cache: %w", err)
	}

	if err := c.wrapper.StoreCred(ctx, cache, creds); err != nil {
		return fmt.Errorf("failed to store renewed credentials: %w", err)
	}

	// Verbose output
	if config.Verbose {
		fmt.Fprintf(os.Stderr, "✓ Successfully renewed Kerberos ticket\n")
		fmt.Fprintf(os.Stderr, "✓ Stored in: %s\n", config.CCachePath)
	}

	// Verify ticket if requested
	if config.Verify {
		if err := c.VerifyTicket(config.CCachePath); err != nil {
			return fmt.Errorf("ticket verification failed: %w", err)
		}
	}

	return nil
}

// generateInitialTicket generates a new Kerberos ticket with password authentication
func (c *krb5Client) generateInitialTicket(config *KinitConfig) error {
	// Validate required fields
	if config.Principal == "" {
		return fmt.Errorf("principal is required")
	}
	if config.Password == "" {
		return fmt.Errorf("password is required")
	}
	if config.CCachePath == "" {
		return fmt.Errorf("cache path is required")
	}

	// Initialize context
	ctx, err := c.wrapper.InitContext()
	if err != nil {
		return fmt.Errorf("failed to initialize krb5 context: %w", err)
	}
	defer c.wrapper.FreeContext(ctx)

	// Parse principal
	princ, err := c.wrapper.ParseName(ctx, config.Principal)
	if err != nil {
		return fmt.Errorf("failed to parse principal: %w", err)
	}
	defer c.wrapper.FreePrincipal(ctx, princ)

	// Allocate credential options
	opts, err := c.wrapper.AllocCredOptions(ctx)
	if err != nil {
		return fmt.Errorf("failed to allocate credential options: %w", err)
	}
	defer c.wrapper.FreeCredOptions(ctx, opts)

	// Set options based on config
	c.wrapper.SetForwardable(opts, config.Forwardable)
	c.wrapper.SetProxiable(opts, config.Proxiable)
	c.wrapper.SetTicketLifetime(opts, config.Lifetime)
	c.wrapper.SetRenewableLife(opts, config.RenewableLife)

	// Get credentials with password
	creds, err := c.wrapper.GetInitCredsPassword(ctx, princ, config.Password, opts)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	defer c.wrapper.FreeCredContents(ctx, creds)

	// Open or create credential cache
	var cache Krb5Ccache
	// Ensure directory exists
	dir := getDir(config.CCachePath)
	if err := c.wrapper.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory '%s': %w", dir, err)
	}

	cache, err = c.wrapper.ResolveCache(ctx, config.CCachePath)
	if err != nil {
		return fmt.Errorf("failed to resolve cache: %w", err)
	}
	defer c.wrapper.CloseCache(ctx, cache)

	// Initialize cache with principal
	if err := c.wrapper.InitializeCache(ctx, cache, princ); err != nil {
		return fmt.Errorf("failed to initialize cache: %w", err)
	}

	// Store credentials
	if err := c.wrapper.StoreCred(ctx, cache, creds); err != nil {
		return fmt.Errorf("failed to store credentials: %w", err)
	}

	// Set cache file permissions (only if file exists)
	if !strings.HasPrefix(config.CCachePath, "KEYRING:") {
		cleanPath := strings.TrimPrefix(config.CCachePath, "FILE:")
		// Check if file exists before trying to chmod
		if _, err := c.wrapper.Stat(cleanPath); err == nil {
			// File exists, set permissions
			if err := c.wrapper.Chmod(cleanPath, 0600); err != nil {
				return fmt.Errorf("failed to set permissions on ccache: %w", err)
			}
		}
	}

	// Verbose output
	if config.Verbose {
		fmt.Fprintf(os.Stderr, "✓ Successfully acquired Kerberos ticket for %s\n", config.Principal)
		fmt.Fprintf(os.Stderr, "✓ Stored in: %s\n", config.CCachePath)
	}

	// Verify ticket if requested
	if config.Verify {
		if err := c.VerifyTicket(config.CCachePath); err != nil {
			return fmt.Errorf("ticket verification failed: %w", err)
		}
	}

	return nil
}

// VerifyTicket verifies a Kerberos ticket exists and is valid
func (c *krb5Client) VerifyTicket(ccachePath string) error {
	return c.wrapper.RunKlist(ccachePath)
}

// getDir extracts the directory path from a file path
func getDir(path string) string {
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if i == 0 {
				return "/"
			}
			return path[:i]
		}
	}
	return "."
}
