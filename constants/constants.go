package constants

// LDAPSearchFilterString is the base LDAP filter for gMSA accounts
const LDAPSearchFilterString = "(objectClass=msDS-GroupManagedServiceAccount)"
const LDAPSearchBase = "ldapsearch -o ldif_wrap=no -LLL -Y GSSAPI -H ldap://"
