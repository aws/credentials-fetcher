#include "daemon.h"

creds_fetcher::Daemon cf_daemon;

int main(int argc, const char *argv[])
{
    parse_options(argc,argv,cf_daemon);

    parse_config_file(cf_daemon.config_file,cf_daemon);

    generate_host_machine_krb_ticket();

    initialize_api();

    // handle kerberos tickets
    // TBD: remove hard coded values and get info from the configuration
    //std::thread(krb_ticket_handler,cf_daemon.krb_ticket_handle_interval, "contoso.com", "webapp04$","").detach();

    initialize_cache(cf_daemon.cf_cache);

    cf_daemon.cf_logger.set_log_level(LOG_NOTICE);

    /*
     * This is a 'new-style daemon', fork() and other book-keeping is not required.
     * https://www.freedesktop.org/software/systemd/man/daemon.html#New-Style%20Daemons
     */

    /*
     * If the daemon does not invoke sd_watchdog_enabled() in the interval, systemd will restart the daemon
     */
    bool watchdog = sd_watchdog_enabled(0, &cf_daemon.watchdog_interval_usecs) > 0;
    if (watchdog) {
        fprintf(stderr, SD_NOTICE "watchdog enabled with interval value = %ld",
                cf_daemon.watchdog_interval_usecs);
    } else {
        fprintf(stderr, SD_ERR "ERROR Cannot setup watchdog, interval value = %ld",
                cf_daemon.watchdog_interval_usecs);
        /* TBD: Use exit code scheme as defined in the LSB recommendations for SysV init scripts */
        exit(EXIT_FAILURE);
    }

    /* Tells the service manager that service startup is finished */
    sd_notify(0, "READY=1");
    int i = 0;
    while(true) {
        usleep(cf_daemon.watchdog_interval_usecs / 2); /* TBD: Replace this later */
        /* Tells the service manager to update the watchdog timestamp */
        sd_notify(0, "WATCHDOG=1");

        /* sd_notifyf() is similar to sd_notify() but takes a printf()-like format string plus arguments. */
        sd_notifyf(0, "STATUS=Watchdog notify count = %d", i); // TBD: Remove later, visible in systemctl status
        cf_daemon.cf_logger.logger(LOG_NOTICE, "log count %d", i); // TBD: Remove later
        ++i;
    }


    return EXIT_SUCCESS;
}
