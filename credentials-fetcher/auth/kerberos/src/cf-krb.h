#ifndef _cf_krb_h_
#define _cf_krb_h_

namespace creds_fetcher{
class CF_krb{
    public:
        void generate_host_machine_krb_ticket();
        void get_krb_ticket(const char *ldap_uri_arg, const char *gmsa_account_name_arg);
    };
}

#endif//_cf_krb_h_
