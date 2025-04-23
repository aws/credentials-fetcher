package kerberos

import (
	"time"
)

// InvalidCharacters defines characters not allowed in paths/names
var InvalidCharacters = []rune{'&', '|', ';', ':', '$', '*', '?', '<', '>', '!', ' ', '\\', '.', ']', '[', '+', '\'', '`', '~', '}', '{', '"', ')', '('}

const (
	InstallPathForDecodeExe = "/usr/sbin/credentials_fetcher_utf16_private.exe"
	InstallPathForAwsCli    = "/usr/bin/aws"
	SecondsInHour           = 3600
	RenewTicketHours        = 4 // Number of hours before expiry to trigger renewal
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
	KrbFilePath        string `json:"krb_file_path"`
	ServiceAccountName string `json:"service_account_name"`
	DomainName         string `json:"domain_name"`
	DomainlessUser     string `json:"domainless_user"`
	DistinguishedName  string `json:"distinguished_name"`
	CredspecInfo       string `json:"credspec_info"`
}
