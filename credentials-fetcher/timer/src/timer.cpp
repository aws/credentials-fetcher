#include "daemon.h"
#include <chrono>

void krb_ticket_handler( unsigned int interval, std::string domain_name,
                         std::string gmsa_account_name, const char* krb_ccname,
                         creds_fetcher::Daemon& cf_daemon )
{
    while ( true )
    {
        auto x = std::chrono::steady_clock::now() + std::chrono::minutes( interval );
        // TBD: check cache to see if the ticket need re-creation or renewal
        // TBD: get multiple service accounts and loop through each of them to re-create/renew
        // tickets

        // TBD:: *** This must exit during shutdown or during errors ***
        std::transform( domain_name.begin(), domain_name.end(), domain_name.begin(),
                        []( unsigned char c ) { return std::toupper( c ); } );
        std::string default_principal = "'" + gmsa_account_name + "'" + "$@" + domain_name;
        //krb_ticket_renewal( default_principal, krb_ccname );
        std::this_thread::sleep_until( x );
    }
}
