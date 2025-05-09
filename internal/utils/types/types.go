package types

import (
	"time"
)

// InvalidCharacters defines characters not allowed in paths/names
var InvalidCharacters = []rune{'&', '|', ';', ':', '$', '*', '?', '<', '>', '!', ' ', '\\', '.', ']', '[', '+', '\'', '`', '~', '}', '{', '"', ')', '('}

const (
	InstallPathForAwsCli = "/usr/bin/aws"
	SecondsInHour        = 3600
	RenewTicketHours     = 4 // Number of hours before expiry to trigger renewal
)

// Ticket represents a Kerberos ticket
type Ticket struct {
	Path           string
	Principal      string
	Domain         string
	CreationTime   time.Time
	ExpirationTime time.Time
	RenewUntil     time.Time
	Flags          []string
}

// TicketInfo contains information about a Kerberos ticket
type TicketInfo struct {
	KrbFilePath        string
	ServiceAccountName string
	DomainName         string
	DomainlessUser     string
	DistinguishedName  string
	CredspecInfo       string
	CredentialArn      string
}

// CredentialSpec represents a parsed credential spec
type CredentialSpec struct {
	DomainName         string
	ServiceAccountName string
	CredentialArn      string
}

// ManagedPasswordBlob represents the structure of the msDS-ManagedPassword blob
// This matches the C++ blob_t structure
type ManagedPasswordBlob struct {
	Version                         uint16
	Reserved                        uint16
	Length                          uint32
	CurrentPasswordOffset           uint16
	PreviousPasswordOffset          uint16
	QueryPasswordIntervalOffset     uint16
	UnchangedPasswordIntervalOffset uint16
	// The actual password data follows these fields in the raw blob
}

// Constants for password blob processing
const (
	BlobRemainingBufSize = 1024 // TBD: Fix this, remaining buf size is variable
	GMSAPasswordSize     = 256  // TBD: Get from parsed blob
)
