

// renew the ticket 1 hrs before the expiration
#define RENEW_TICKET_HOURS 1
#define SECONDS_IN_HOUR 3600
// Active Directory uses NetBIOS computer names that do not exceed 15 characters.
// https://learn.microsoft.com/en-us/troubleshoot/windows-server/identity/naming-conventions-for-computer-domain-site-ou
#define HOST_NAME_LENGTH_LIMIT 15

/* Environment variables in /etc/ecs/ecs.config or shell */
#define ENV_CF_GMSA_OU "CF_GMSA_OU"
#define ENV_CF_GMSA_SECRET_NAME "CREDENTIALS_FETCHER_SECRET_NAME_FOR_DOMAINLESS_GMSA"
#define ENV_CF_DOMAIN_CONTROLLER "DOMAIN_CONTROLLER_GMSA"
#define ENV_CF_DISTINGUISHED_NAME "CF_GMSA_DISTINGUISHED_NAME"

extern "C" int my_kinit_main(int, char **);
