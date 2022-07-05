#ifndef _cf_krb_h_
#define _cf_krb_h_

#include <stdint.h>

namespace creds_fetcher
{

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e
typedef struct blob_t_
{
    uint16_t version;
    uint16_t reserved;
    uint32_t length;
    uint16_t current_password_offset;
    uint16_t previous_password_offset;
    uint16_t query_password_interval_offset;
    uint16_t unchanged_password_interval_offset;
#define BLOB_REMAINING_BUF_SIZE 1024 /* TBD:: Fix this, remaining buf size is variable */
#define GMSA_PASSWORD_SIZE 256       /* TBD: Get from parsed blob */
    uint8_t buf[1024];
    /* TBD:: Add remaining fields here */
} blob_t;

class CF_krb
{
  public:
    CF_krb();
};
} // namespace creds_fetcher
int generate_host_machine_krb_ticket(const char *krb_ccname = "");
int get_krb_ticket(const char *ldap_uri_arg, const char *gmsa_account_name_arg);
void krb_ticket_renewal(const char *defaultprincipal, const char *krb_ccname = "");
void krb_ticket_creation(const char *ldap_uri_arg, const char *gmsa_account_name_arg, const char *krb_ccname = "");

#endif // _cf_krb_h_
