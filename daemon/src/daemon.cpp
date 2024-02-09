#include "daemon.h"
#include <iostream>
#include <libgen.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <chrono>

creds_fetcher::Daemon cf_daemon;

struct thread_info
{                        /* Used as argument to thread_start() */
    pthread_t thread_id; /* ID returned by pthread_create() */
    int thread_num;      /* Application-defined thread # */
    char* argv_string;   /* From command-line argument */
};

static const char* grpc_thread_name = "grpc_thread";

static void systemd_shutdown_signal_catcher( int signo )
{
    cf_daemon.got_systemd_shutdown_signal = 1;
}

#define handle_error_en( en, msg )                                                                 \
    do                                                                                             \
    {                                                                                              \
        errno = en;                                                                                \
        perror( msg );                                                                             \
    } while ( 0 )

#define handle_error( msg )                                                                        \
    do                                                                                             \
    {                                                                                              \
        perror( msg );                                                                             \
    } while ( 0 )

#define ENV_CF_CRED_SPEC_FILE "CF_CRED_SPEC_FILE"

/**
 * grpc_thread_start - used in pthread_create
 * @param arg - thread info
 * @return pthread name
 */
void* grpc_thread_start( void* arg )
{
    struct thread_info* tinfo = (struct thread_info*)arg;

    printf( "Thread %d: top of stack near %p; argv_string=%s\n", tinfo->thread_num, (void*)&tinfo,
            tinfo->argv_string );

    RunGrpcServer( cf_daemon.unix_socket_dir, cf_daemon.krb_files_dir, cf_daemon.cf_logger,
                   &cf_daemon.got_systemd_shutdown_signal, cf_daemon.aws_sm_secret_name );

    return tinfo->argv_string;
}

/**
 * refresh_krb_tickets - used in pthread_create
 * @param arg - thread info
 * @return pthread name
 */
void* refresh_krb_tickets_thread_start( void* arg )
{
    struct thread_info* tinfo = (struct thread_info*)arg;

    printf( "Thread %d: top of stack near %p; argv_string=%s\n", tinfo->thread_num, (void*)&tinfo,
            tinfo->argv_string );

    // ticket refresh
    krb_ticket_renew_handler( cf_daemon );

    return tinfo->argv_string;
}

/**
 * truncate_log_files - used in pthread_create
 * @param arg - thread info
 * @return pthread name
 */
void* truncate_file_logs_thread_start( void* arg )
{
    struct thread_info* tinfo = (struct thread_info*)arg;

    printf( "Thread %d: top of stack near %p; argv_string=%s\n", tinfo->thread_num, (void*)&tinfo,
            tinfo->argv_string );

    //trucate log files
    truncate_log_files();

    return tinfo->argv_string;
}


/**
 * Create one pthread
 * @param func - pthread function
 * @param pthread_arg - pthread function parameter
 * @param stack_size - pthread stack defaults to -1
 * @return pair of return code and pointer to pthread
 */
std::pair<int, void*> create_pthread( void* ( *func )(void*), const char* pthread_arg,
                                      ssize_t stack_size )
{
    pthread_attr_t attr;
    int status;
    const int num_threads = 1;

    if ( func == nullptr || pthread_arg == nullptr )
    {
        return std::make_pair( EXIT_FAILURE, nullptr );
    }
    /* Initialize thread creation attributes. */

    status = pthread_attr_init( &attr );
    if ( status != 0 )
    {
        handle_error_en( status, "pthread_attr_init" );
        return std::make_pair( EXIT_FAILURE, nullptr );
    }

    if ( stack_size > 0 )
    {
        status = pthread_attr_setstacksize( &attr, stack_size );
        if ( status != 0 )
        {
            handle_error_en( status, "pthread_attr_setstacksize" );
            return std::make_pair( EXIT_FAILURE, nullptr );
        }
    }

    /* Allocate memory for pthread_create() arguments. */
    struct thread_info* tinfo = (thread_info*)calloc( num_threads, sizeof( *tinfo ) );
    if ( tinfo == NULL )
    {
        handle_error( "calloc" );
        return std::make_pair( EXIT_FAILURE, nullptr );
    }
    tinfo->argv_string = (char*)pthread_arg;

    status = pthread_create( &tinfo->thread_id, &attr, func, tinfo );
    if ( status != 0 )
    {
        handle_error_en( status, "pthread_create" );
        return std::make_pair( EXIT_FAILURE, nullptr );
    }

    /* Destroy the thread attributes object, since it is no longer needed. */
    status = pthread_attr_destroy( &attr );
    if ( status != 0 )
    {
        handle_error_en( status, "pthread_attr_destroy" );
        return std::make_pair( EXIT_FAILURE, nullptr );
    }

    return std::make_pair( EXIT_SUCCESS, tinfo );
}

void truncate_log_files()
{
    int truncate_interval = 60;
    while ( !cf_daemon.got_systemd_shutdown_signal )
    {
        try
        {
            auto x = std::chrono::steady_clock::now() + std::chrono::minutes ( truncate_interval );
            std::this_thread::sleep_until( x );
            int number_of_log_lines = 1000;
            std::string log_path = "/var/credentials-fetcher/logging";
            std::string cmd = "wc -l " + log_path + "/credentials-fetcher.log | awk '{print $1}'";
            static std::pair<int, std::string> result = exec_shell_cmd( cmd );

            int num = number_of_log_lines;
            if(!result.second.empty())
            {
                num = stoi( result.second );
            }

            // check if log file have more than 1000 lines
            if ( num >= number_of_log_lines )
            {
               cmd = "tail -500 "+ log_path + "/credentials-fetcher.log > "
                      + log_path + "/tmp.log";

                result = exec_shell_cmd( cmd );
                if ( result.first != 0 )
                {
                    std::cout << getCurrentTime() << '\t' << "ERROR: truncating log file failed" << std::endl;
                }
                cmd = "cp -f " + log_path + "/tmp.log " +log_path + "/credentials-fetcher.log";

                result = exec_shell_cmd( cmd );
                if ( result.first != 0 )
                {
                    std::cout << getCurrentTime() << '\t' << "ERROR: copy file failed" <<
                        std::endl;
                }
            }
            std::cout << getCurrentTime() << '\t' << "INFO: log file truncate successful" <<
                                                              std::endl;
        }
        catch ( const std::exception& ex  )
        {
            std::cout << getCurrentTime() << '\t' << "ERROR: failed truncate log file" << ex.what()
                      << std::endl;
        }
    }
    return;
}

int parse_cred_file_path(const std::string& cred_file_path, std::string& cred_file, std::string& cred_file_lease_id )
{
    size_t colon_delim_pos;
    char path_lease_delimiter = ':';

    if (cred_file_path.empty())
        return EXIT_FAILURE;

    colon_delim_pos = cred_file_path.find(path_lease_delimiter);

    //If the : delimiter is not found, then assume the cred_file_path is just the path to cred spec file and use the default lease id
    if (colon_delim_pos == std::string::npos)
    {
        cred_file = cred_file_path;
        cred_file_lease_id = DEFAULT_CRED_FILE_LEASE_ID;

        return EXIT_SUCCESS;
    }

    cred_file = cred_file_path.substr(0, colon_delim_pos);
    cred_file_lease_id = cred_file_path.substr(colon_delim_pos+1);

    return EXIT_SUCCESS;
}

int main( int argc, const char* argv[] )
{
    std::pair<int, void*> pthread_status;
    std::string cred_file;
    std::string cred_file_lease_id;
    void* grpc_pthread;
    void* krb_refresh_pthread;
    void* truncate_file_logs_pthread;

    int status = parse_options( argc, argv, cf_daemon );
    if ( status != EXIT_SUCCESS )
    {
        exit( EXIT_FAILURE );
    }

    cf_daemon.krb_files_dir = CF_KRB_DIR;
    cf_daemon.logging_dir = CF_LOGGING_DIR;
    cf_daemon.unix_socket_dir = CF_UNIX_DOMAIN_SOCKET_DIR;

    std::cout << "credentials-fetcher daemon has started and running"  << std::endl;
    std::cout << "on request failures check logs located at " + cf_daemon.logging_dir << std::endl;;

    if ( getenv(ENV_CF_CRED_SPEC_FILE) != NULL)
    {
        int parseResult = parse_cred_file_path( getenv(ENV_CF_CRED_SPEC_FILE), 
                                                cred_file,
                                                cred_file_lease_id);

        if (parseResult == EXIT_FAILURE)
        {
            std::cout << "Failed parsing environment variable " << getenv(ENV_CF_CRED_SPEC_FILE) << std::endl;
            cf_daemon.cf_logger.logger( LOG_ERR, "Failed parsing environment variable %s", getenv(ENV_CF_CRED_SPEC_FILE) );

            exit( EXIT_FAILURE);
        }

        if (!std::filesystem::exists( cred_file))
        {
            cred_file_lease_id.clear();
            std::cout << "Ignoring CF_CREF_FILE, file " << cred_file << " not found" << std::endl;
        }
        else
        {
            cf_daemon.cred_file = cred_file;
        }
    }

    /**
     * Domain name and gmsa account are usually set in APIs.
     * The options below can be used as a test.
     */
    cf_daemon.domain_name = CF_TEST_DOMAIN_NAME;
    cf_daemon.gmsa_account_name = CF_TEST_GMSA_ACCOUNT;

    std::cout << "krb_files_dir = " << cf_daemon.krb_files_dir << std::endl;
    //std::cout << "cred_file = " << cf_daemon.cred_file <<  " (lease id: " << cred_file_lease_id
             //   << ")" << std::endl;
    std::cout << "logging_dir = " << cf_daemon.logging_dir << std::endl;
    std::cout << "unix_socket_dir = " << cf_daemon.unix_socket_dir << std::endl;

    if ( cf_daemon.run_diagnostic )
    {
        exit(  read_meta_data_json_test() ||
              read_meta_data_invalid_json_test() || renewal_failure_krb_dir_not_found_test() ||
              write_meta_data_json_test() );
    }

    struct sigaction sa;
    cf_daemon.got_systemd_shutdown_signal = 0;
    memset( &sa, 0, sizeof( struct sigaction ) );
    sa.sa_handler = &systemd_shutdown_signal_catcher;
    if ( sigaction( SIGTERM, &sa, NULL ) == -1 )
    {
        perror( "sigaction" );
        return EXIT_FAILURE;
    }

    /* We need to run three parallel processes */
    // 1. Systemd - daemon
    // 2. grpc server
    // 3. timer to run every 45 min

    if ( !cf_daemon.cred_file.empty() ) {
        cf_daemon.cf_logger.logger( LOG_INFO, "Credential file exists %s", cf_daemon.cred_file.c_str() );
        
        int specFileReturn = ProcessCredSpecFile(cf_daemon.krb_files_dir, cf_daemon.cred_file, cf_daemon.cf_logger, cred_file_lease_id);
        if (specFileReturn == EXIT_FAILURE) {
            std::cout << "ProcessCredSpecFile() non 0 " << std::endl;
            exit( EXIT_FAILURE );
        }
    }
    
    /* Create one pthread for gRPC processing */
    pthread_status =
        create_pthread( grpc_thread_start, grpc_thread_name, -1 );
    if ( pthread_status.first < 0 )
    {
        cf_daemon.cf_logger.logger( LOG_ERR, "Error %d: Cannot create pthreads",
                                    pthread_status.first );
        exit( EXIT_FAILURE );
    }
    grpc_pthread = pthread_status.second;
    cf_daemon.cf_logger.logger( LOG_INFO, "grpc pthread is at %p", grpc_pthread );

    // initialize file logging
    cf_daemon.cf_logger.init_file_logger();
        
    /* Create pthread for refreshing krb tickets */
    pthread_status =
        create_pthread( refresh_krb_tickets_thread_start, "krb_ticket_refresh_thread", -1 );
    if ( pthread_status.first < 0 )
    {
        cf_daemon.cf_logger.logger( LOG_ERR, "Error %d: Cannot create pthreads",
                                    pthread_status.first );
        exit( EXIT_FAILURE );
    }
    krb_refresh_pthread = pthread_status.second;
    cf_daemon.cf_logger.logger( LOG_INFO, "krb refresh pthread is at %p", krb_refresh_pthread );

    /* Create pthread for truncate file logs */
    pthread_status =
        create_pthread( truncate_file_logs_thread_start, "truncate_file_logs", -1 );
    if ( pthread_status.first < 0 )
    {
        cf_daemon.cf_logger.logger( LOG_ERR, "Error %d: Cannot create pthreads",
                                    pthread_status.first );
        exit( EXIT_FAILURE );
    }
    truncate_file_logs_pthread = pthread_status.second;
    cf_daemon.cf_logger.logger( LOG_INFO, "truncate file logs is at %p",
                                truncate_file_logs_pthread );


    cf_daemon.cf_logger.set_log_level( LOG_NOTICE );

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
    while ( !cf_daemon.got_systemd_shutdown_signal )
    {
        usleep( cf_daemon.watchdog_interval_usecs / 2 ); /* TBD: Replace this later */
        /* Tells the service manager to update the watchdog timestamp */
        sd_notify( 0, "WATCHDOG=1" );

        /* sd_notifyf() is similar to sd_notify() but takes a printf()-like format string plus
         * arguments. */
        sd_notifyf( 0, "STATUS=Watchdog notify count = %d",
                    i ); // TBD: Remove later, visible in systemctl status
        ++i;
    }

    return EXIT_SUCCESS;
}

