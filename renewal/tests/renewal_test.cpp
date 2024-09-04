#include "daemon.h"
#include <stdlib.h>

int renewal_failure_krb_dir_not_found_test()
{
    Daemon cf_daemon;

    int result = krb_ticket_renew_handler( cf_daemon );

    if ( result != -1 )
    {
        std::cout << "\nkrb dir not found test is failed" << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "\nkrb dir not found test is successful" << std::endl;
    return EXIT_SUCCESS;
}
