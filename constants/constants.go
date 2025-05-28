package constants

// LDAP-related constants
const (
	// LDAPSearchFilterString is the base LDAP filter for gMSA accounts
	LDAPManagedPasswordSearchFilter = "(objectClass=msDS-GroupManagedServiceAccount)" // #nosec G101

	// LDAPSearchCommand is the command to execute for LDAP searches
	LDAPSearchCommand = "ldapsearch"

	// LDAPDistinguishedNameSearchFilter is the filter used to search for distinguished names
	LDAPDistinguishedNameSearchFilter = "(CN=%s)"
)

// Directory and file path constants
const (
	// DefaultSocketDir is the directory where the network socket will be created
	DefaultSocketDir = "/var/credentials-fetcher/socket"

	// DefaultKrbFilesDir is the directory where Kerberos files are stored
	DefaultKrbFilesDir = "/var/credentials-fetcher/krbdir"
)

// Application configuration constants
const (
	// NumberofWaitGroups for watchdog and gRPC server
	NumberofWaitGroups = 2

	// KlistDateTimeFormat is the standard date time format used for parsing Kerberos klist output
	KlistDateTimeFormat = "01/02/2006 15:04:05"

	// Default Secret for user principal
	DefaultAWSSecretName = "" // TODO: parameterize this
)

// Credential-related constants
const (
	// LeaseIDLength is the length of generated lease IDs
	LeaseIDLength = 10

	// InputCredentialsLength is the default length for credential inputs
	InputCredentialsLength = 104

	// Maximum length constraints for credentials
	MaxUsernameLength = 104
	MaxPasswordLength = 104
	MaxDomainLength   = 253

	// InvalidUsernameChars contains characters not allowed in username
	InvalidUsernameChars = "&:][+|;$*?<>!/\\\\'`~"

	// DomainRegexPattern is the regex pattern for validating domain names
	DomainRegexPattern = `^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*$`
)

// ECS config constants
const (
	// ECSConfigFilePath is the path to the ECS configuration file
	ECSConfigFilePath = "/etc/ecs/ecs.config"
	// Environment variable names as defined in the original C++ code
	EnvCFGmsaOU            = "CF_GMSA_OU"
	EnvCFGmsaSecretName    = "CREDENTIALS_FETCHER_SECRET_NAME_FOR_DOMAINLESS_GMSA"
	EnvCFDomainController  = "DOMAIN_CONTROLLER_GMSA"
	EnvCFDistinguishedName = "CF_GMSA_DISTINGUISHED_NAME"
)
