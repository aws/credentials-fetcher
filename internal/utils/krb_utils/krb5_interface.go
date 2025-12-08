package krb_utils

import (
	"golang.a2z.com/CredentialsFetcherV2/internal/utils/krb_utils/cgo"
)

// Re-export types from cgo package for convenience
type (
	Krb5Context     = cgo.Krb5Context
	Krb5Principal   = cgo.Krb5Principal
	Krb5Ccache      = cgo.Krb5Ccache
	Krb5Creds       = cgo.Krb5Creds
	Krb5CredOptions = cgo.Krb5CredOptions
	Krb5Wrapper     = cgo.Krb5Wrapper
)

// Krb5Client is a high-level interface for Kerberos operations
// It provides business logic on top of the low-level Krb5Wrapper
type Krb5Client interface {
	// GenerateTicket generates a Kerberos ticket with the given configuration
	GenerateTicket(config *KinitConfig) error

	// VerifyTicket verifies a Kerberos ticket using klist
	VerifyTicket(ccachePath string) error
}

// DefaultKrb5Wrapper is the default CGO-based implementation
var DefaultKrb5Wrapper Krb5Wrapper = cgo.NewCGOWrapper()

// DefaultKrb5Client is the default implementation using CGO
var DefaultKrb5Client Krb5Client = NewKrb5Client(DefaultKrb5Wrapper)
