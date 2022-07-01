#include "daemon.h"
#include <chrono>

void krb_ticket_handler(unsigned int interval, const char *ldap_uri_arg, const char *gmsa_account_name_arg, const char* krb_ccname)
{
    while (true)
    {
       auto x = std::chrono::steady_clock::now() + std::chrono::seconds(interval);
       // TBD: check cache to see if the ticket need re-creation or renewal
       // TBD: get multiple service accounts and loop through each of them to re-create/renew tickets
       if(true)
       {
           krb_ticket_creation(ldap_uri_arg, gmsa_account_name_arg, krb_ccname);
       }
       else{
          std::string domainname = std::string(ldap_uri_arg);
          for (auto&c : domainname)c = toupper(c);
          std::string defaultprincipal = "'" + std::string(gmsa_account_name_arg) + "'" + "$@" + domainname;
          krb_ticket_renewal(defaultprincipal.c_str(), krb_ccname);
       }


       std::this_thread::sleep_until(x);
    }
}


