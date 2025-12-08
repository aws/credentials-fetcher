package krb_utils

import (
	"fmt"
	"os"
)

const (
	version = "1.0.0"
)

// KinitConfig holds the configuration for kinit.
// Default values: Forwardable=true, Proxiable=false, Verify=true, Verbose=false
// Lifetime and RenewableLife default to 0 (uses KDC defaults, typically 10 hours for lifetime)
type KinitConfig struct {
	Principal     string // REQUIRED: Kerberos principal (e.g., user@EXAMPLE.COM)
	Password      string // Password for authentication (REQUIRED for initial auth, not needed for renewal)
	PasswordFile  string // Not used in library mode, kept for compatibility
	CCachePath    string // REQUIRED: Path to credential cache file
	Lifetime      int32  // Ticket lifetime in seconds (default: 0 = KDC default, typically 10h)
	RenewableLife int32  // Renewable lifetime in seconds (default: 0 = not renewable)
	Forwardable   bool   // Make ticket forwardable (default: true)
	Proxiable     bool   // Make ticket proxiable (default: false)
	Verify        bool   // Verify ticket after creation (default: true)
	Verbose       bool   // Enable verbose output (default: false)
	PasswordStdin bool   // Not used in library mode, kept for compatibility
	RenewTicket   bool   // Renew existing ticket instead of creating new one (like 'kinit -R', no password required)
}

// GenerateKerberosTicket generates a Kerberos ticket using the provided configuration.
// This is the main entry point for the library that uses the default CGO implementation.
func GenerateKerberosTicket(config *KinitConfig) error {
	if DefaultKrb5Client == nil {
		return fmt.Errorf("DefaultKrb5Client is not initialized")
	}
	return DefaultKrb5Client.GenerateTicket(config)
}

// GenerateKerberosTicketWithClient generates a Kerberos ticket using a custom Krb5Client.
// This is useful for testing with a mock client.
func GenerateKerberosTicketWithClient(config *KinitConfig, client Krb5Client) error {
	return client.GenerateTicket(config)
}

// NewKinitConfig creates a new KinitConfig with default values
func NewKinitConfig(principal, password string) *KinitConfig {
	return &KinitConfig{
		Principal:   principal,
		Password:    password,
		Forwardable: true,
		Verify:      true,
		Verbose:     false,
	}
}

// NewKinitConfigWithCache creates a new KinitConfig with a specified cache path
func NewKinitConfigWithCache(principal, password, ccachePath string) *KinitConfig {
	config := NewKinitConfig(principal, password)
	config.CCachePath = ccachePath
	return config
}

// VerifyTicket verifies a Kerberos ticket by running klist using the default client
func VerifyTicket(ccachePath string) error {
	if DefaultKrb5Client == nil {
		return fmt.Errorf("DefaultKrb5Client is not initialized")
	}
	return DefaultKrb5Client.VerifyTicket(ccachePath)
}

// PrintVersion prints the version information
func PrintVersion() {
	fmt.Fprintf(os.Stderr, "go-kinit version %s\n", version)
}
