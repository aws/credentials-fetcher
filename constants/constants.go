package constants

// LDAPSearchFilterString is the base LDAP filter for gMSA accounts
const LDAPSearchFilterString = "(objectClass=msDS-GroupManagedServiceAccount)"

// LDAPSearchBase string is the base string used to build the ldap search command
const LDAPSearchBase = "ldapsearch -o ldif_wrap=no -LLL -Y GSSAPI -H ldap://"

// defaultSocketDir is the directory where the network socket will be created
const DefaultSocketDir = "/var/credentials-fetcher/socket"
