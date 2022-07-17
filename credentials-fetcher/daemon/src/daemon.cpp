#include "daemon.h"
#include <iostream>
#include <stdlib.h>

creds_fetcher::Daemon cf_daemon;

struct thread_info
{                        /* Used as argument to thread_start() */
    pthread_t thread_id; /* ID returned by pthread_create() */
    int thread_num;      /* Application-defined thread # */
    char* argv_string;   /* From command-line argument */
};

#define handle_error_en( en, msg )                                                                 \
    do                                                                                             \
    {                                                                                              \
        errno = en;                                                                                \
        perror( msg );                                                                             \
        return ( EXIT_FAILURE );                                                                   \
    } while ( 0 )

#define handle_error( msg )                                                                        \
    do                                                                                             \
    {                                                                                              \
        perror( msg );                                                                             \
        return ( EXIT_FAILURE );                                                                   \
    } while ( 0 )

/**
 * grpc_thread_start - used in pthread_create
 * @param arg - thread info
 * @return pthread name
 */
void* grpc_thread_start( void* arg )
{
    struct thread_info* tinfo = (struct thread_info*)arg;
    tinfo->argv_string = (char*)"grpc_thread";

    printf( "Thread %d: top of stack near %p; argv_string=%s\n", tinfo->thread_num, (void*)&tinfo,
            tinfo->argv_string );

#if FEDORA_FOUND
    RunGrpcServer( cf_daemon.unix_socket_path, cf_daemon.cf_logger );
#endif

    return tinfo->argv_string;
}

/**
 * Create one pthread for grpc processing
 * @return 0 if successful
 */
int create_grpc_pthread()
{
    pthread_attr_t attr;
    ssize_t stack_size;
    int s;
    int num_threads = 1; /* One thread for grpc processing */

    stack_size = -1;

    /* Initialize thread creation attributes. */

    s = pthread_attr_init( &attr );
    if ( s != 0 )
        handle_error_en( s, "pthread_attr_init" );

    if ( stack_size > 0 )
    {
        s = pthread_attr_setstacksize( &attr, stack_size );
        if ( s != 0 )
            handle_error_en( s, "pthread_attr_setstacksize" );
    }

    /* Allocate memory for pthread_create() arguments. */

    struct thread_info* tinfo = (thread_info*)calloc( num_threads, sizeof( *tinfo ) );
    if ( tinfo == NULL )
        handle_error( "calloc" );

    /* Create one thread for each command-line argument. */

    s = pthread_create( &tinfo->thread_id, &attr, &grpc_thread_start, &tinfo );
    if ( s != 0 )
        handle_error_en( s, "pthread_create" );

    /* Destroy the thread attributes object, since it is no
       longer needed. */

    s = pthread_attr_destroy( &attr );
    if ( s != 0 )
        handle_error_en( s, "pthread_attr_destroy" );

    return EXIT_SUCCESS;
}

int main( int argc, const char* argv[] )
{
    int status;

    status = parse_options( argc, argv, cf_daemon );
    if ( status < 0 )
    {
        cf_daemon.cf_logger.logger( LOG_ERR, "Error %d: Cannot get parse command line options",
                                    status );
        exit( EXIT_FAILURE );
    }

    status = parse_config_file( cf_daemon );
    if ( status < 0 )
    {
        cf_daemon.cf_logger.logger( LOG_ERR, "Error %d: Cannot parse config file", status );
        exit( EXIT_FAILURE );
    }

    /* TBD: we need to run three parallel processes */
    // 1. Systemd - daemon
    // 2. grpc server
    // 3. timer to run every 45 min
    // un-comment to run grpc server, ensure grpc is installed already

    /* Create one pthread for gRPC processing */
    status = create_grpc_pthread();
    if ( status < 0 )
    {
        cf_daemon.cf_logger.logger( LOG_ERR, "Error %d: Cannot create pthreads", status );
    }

    status = get_machine_krb_ticket( cf_daemon.domain_name, cf_daemon.cf_logger );
    if ( status < 0 )
    {
        cf_daemon.cf_logger.logger( LOG_ERR, "Error %d: Cannot get machine krb ticket", status );
    }

    // TBD: remove hard coded values and get info from the configuration
    // std::thread(krb_ticket_handler,cf_daemon.krb_ticket_handle_interval, "contoso.com",
    // "webapp04$","").detach();

    // this is a test, remove this later
    std::string krb_ccname = cf_daemon.krb_files_dir + std::string( "/ccname_XXXXXX" );
    char krb_ccname_str[PATH_MAX];
    strncpy( krb_ccname_str, krb_ccname.c_str(), PATH_MAX );
    status = mkstemp( krb_ccname_str ); // XXXXXX as per mkstemp man page
    if ( status < 0 )
    {
        cf_daemon.cf_logger.logger( LOG_ERR, "Error %d: Cannot make temporary file", status );
        // TBD:: Add error handling
    }

    std::pair<int, std::string> gmsa_ticket_result =
        get_gmsa_krb_ticket( cf_daemon.domain_name, cf_daemon.gmsa_account_name, krb_ccname_str,
                             cf_daemon.krb_files_dir, cf_daemon.cf_logger );
    if ( gmsa_ticket_result.first < 0 )
    {
        cf_daemon.cf_logger.logger( LOG_ERR, "ERROR: Cannot get gMSA krb ticket", status );
    }
    else
    {
        cf_daemon.cf_logger.logger( LOG_INFO, "gMSA ticket is at %s", gmsa_ticket_result.second );
        std::cout << "gMSA ticket is at " << gmsa_ticket_result.second << std::endl;
    }

    cf_daemon.cf_logger.set_log_level( LOG_NOTICE );
    // initialize_cache( cf_daemon.cf_cache );

    char* daemon_started_by_systemd = getenv( "CREDENTIALS_FETCHERD_STARTED_BY_SYSTEMD" );

    if ( daemon_started_by_systemd != NULL )
    {
        /*
         * This is a 'new-style daemon', fork() and other book-keeping is not required.
         * https://www.freedesktop.org/software/systemd/man/daemon.html#New-Style%20Daemons
         */

        /*
         * If the daemon does not invoke sd_watchdog_enabled() in the interval, systemd will restart
         * the daemon
         */
        bool watchdog = sd_watchdog_enabled( 0, &cf_daemon.watchdog_interval_usecs ) > 0;
        if ( watchdog )
        {
            fprintf( stderr, SD_NOTICE "watchdog enabled with interval value = %ld",
                     cf_daemon.watchdog_interval_usecs );
        }
        else
        {
            fprintf( stderr, SD_ERR "ERROR Cannot setup watchdog, interval value = %ld",
                     cf_daemon.watchdog_interval_usecs );
            /* TBD: Use exit code scheme as defined in the LSB recommendations for SysV init scripts
             */
            exit( EXIT_FAILURE );
        }
    }

    /* Tells the service manager that service startup is finished */
    sd_notify( 0, "READY=1" );
    int i = 0;
    while ( true )
    {
        usleep( cf_daemon.watchdog_interval_usecs / 2 ); /* TBD: Replace this later */
        /* Tells the service manager to update the watchdog timestamp */
        sd_notify( 0, "WATCHDOG=1" );

        /* sd_notifyf() is similar to sd_notify() but takes a printf()-like format string plus
         * arguments. */
        sd_notifyf( 0, "STATUS=Watchdog notify count = %d",
                    i ); // TBD: Remove later, visible in systemctl status
        cf_daemon.cf_logger.logger( LOG_NOTICE, "log count %d", i ); // TBD: Remove later
        ++i;
    }

    return EXIT_SUCCESS;
}
