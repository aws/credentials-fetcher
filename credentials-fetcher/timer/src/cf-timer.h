#ifndef _cf_timer_h_
#define _cf_timer_h_

namespace creds_fetcher
{
    class CF_timer
    {
      public:
        CF_timer();
    };
} // namespace creds_fetcher
// TBD: we need to pass list of gmsa_service_accounts
void krb_ticket_handler( unsigned int interval, const char* ldap_uri_arg,
                         const char* gmsa_account_name_arg, const char* krb_ccname = "" );

#endif // _cf_timer_h_