package constants

// LDAPSearchFilterString is the base LDAP filter for gMSA accounts
const LDAPSearchFilterString = "(objectClass=msDS-GroupManagedServiceAccount)"

// LDAPSearchBase string is the base string used to build the ldap search command
const LDAPSearchBase = "ldapsearch -o ldif_wrap=no -LLL -Y GSSAPI -H ldap://"

// DefaultSocketDir is the directory where the network socket will be created
const DefaultSocketDir = "/var/credentials-fetcher/socket"

// One WaitGroup for watchdog and one for gRPC server
const NumberofWaitGroups = 2

// KlistDateTimeFormat is the standard date time format used for parsing Kerberos klist output
const KlistDateTimeFormat = "01/02/2006 15:04:05"

const LeaseIDLength = 16

// Default Secret for user principal
const DefaultAWSSecretName = "aws/directoryservice/contoso/gmsa"

// DefaultKrbFilesDir is the directory where Kerberos files are stored
const DefaultKrbFilesDir = "/var/credentials-fetcher/krbdir"
