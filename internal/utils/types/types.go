package types

import (
	"time"

	"golang.a2z.com/CredentialsFetcherV2/constants"
)

// InvalidCredSpecPathChars defines characters not allowed in credential spec mount paths.
// Derived from constants.InvalidSAMAccountNameChars, excluding '/' since paths contain forward slashes.
var InvalidCredSpecPathChars []rune

func init() {
	for _, r := range constants.InvalidSAMAccountNameChars {
		if r != '/' {
			InvalidCredSpecPathChars = append(InvalidCredSpecPathChars, r)
		}
	}
}

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

// KerberosTicketArnMapping contains mapping between credential spec ARN and Kerberos file path
type KerberosTicketArnMapping struct {
	CredentialSpecArn           string
	KrbFilePath                 string
	CredentialDomainlessUserArn string
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
