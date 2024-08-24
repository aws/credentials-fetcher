

// renew the ticket 1 hrs before the expiration
#define RENEW_TICKET_HOURS 1
#define SECONDS_IN_HOUR 3600
// Active Directory uses NetBIOS computer names that do not exceed 15 characters.
// https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/naming-conventions-for-computer-domain-site-ou


/* Environment variables in /etc/ecs/ecs.config or shell */
#define HOST_NAME_LENGTH_LIMIT 15
#define ENV_CF_GMSA_OU "CF_GMSA_OU"
#define ENV_CF_GMSA_BASE_DN "CREDENTIALS_FETCHER_GMSA_BASE_DN" // baseObject scope - only the entry specified by the search base DN should be considered.
#define ENV_CF_GMSA_SECRET_NAME "CREDENTIALS_FETCHER_SECRET_NAME_FOR_DOMAINLESS_GMSA"
#define ENV_CF_DOMAIN_CONTROLLER "DOMAIN_CONTROLLER_GMSA"

extern "C" int my_kinit_main(int, char **);
