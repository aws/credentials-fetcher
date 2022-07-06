#include "daemon.h"
#include <boost/algorithm/string.hpp>
#include <glib.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <utility>
#include <vector>

/**
 * Execute a shell command such as "ls /tmp/"
 * output is a pair of error code and output log
 * @param cmd - command to be executed in shell
 * @return result pair(error-code, output log of shell execution)
 */
static std::pair<int, std::string> exec_shell_cmd( std::string cmd )
{
    std::string output;
    char line[80];

    FILE* pFile = popen( cmd.c_str(), "r" );
    if ( pFile == nullptr )
    {
        std::pair<int, std::string> result = std::pair<int, std::string>( -1, std::string( "" ) );
        return result;
    }

    while ( fgets( line, sizeof( line ), pFile ) != nullptr )
    {
        output += std::string( line );
    }
    int error_code = pclose( pFile );

    std::pair<int, std::string> result = std::pair<int, std::string>( error_code, output );
    return result;
}

/**
 * If the host is domain-joined, the result is of the form EC2AMAZ-Q5VJZQ$@CONTOSO.COM'
 * @param domain_name: Expected domain name as per configuration
 * @return result pair<int, std::string> (error-code - 0 if successful
 *                          string of the form EC2AMAZ-Q5VJZQ$@CONTOSO .COM')
 */
static std::pair<int, std::string> get_machine_principal( std::string domain_name )
{
    std::pair<int, std::string> result;

    std::pair<int, std::string> hostname_result = exec_shell_cmd( "hostname -s | tr -d '\n'" );
    if ( hostname_result.first != 0 )
    {
        result.first = hostname_result.first;
        return result;
    }

    std::pair<int, std::string> realm_name_result =
        exec_shell_cmd( "realm list | grep  'realm-name' | cut -f2 -d: | tr -d ' ' | tr -d '\n'" );
    if ( realm_name_result.first != 0 )
    {
        result.first = realm_name_result.first;
        return result;
    }

    std::pair<int, std::string> domain_name_result =
        exec_shell_cmd( "realm list | grep  'domain-name' | cut -f2 -d: | tr -d ' ' | tr -d '\n'" );
    if ( domain_name_result.first != 0 ||
         ( not std::equal( domain_name_result.second.begin(), domain_name_result.second.end(),
                           domain_name.begin() ) ) )
    {
        result.first = -1;
        return result;
    }

    /**
     * Machine principal is of the format EC2AMAZ-Q5VJZQ$@CONTOSO.COM'
     */
    result.first = 0;
    result.second = hostname_result.second + "$@" + realm_name_result.second;

    return result;
}

/**
 * This function generates the kerberos ticket for the host machine.
 * It uses machine keytab located at /etc/krb5.keytab to generate the ticket.
 * @param cf_daemon - parent daemon object
 * @return error-code - 0 if successful
 */
int get_machine_krb_ticket( std::string domain_name, creds_fetcher::CF_logger& cf_logger )
{
    std::pair<int, std::string> result;

    result = get_machine_principal( std::move(domain_name) );
    if ( result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, "ERROR: %s:%d invalid machine principal", __func__, __LINE__ );
        return result.first;
    }

    // kinit -kt /etc/krb5.keytab  'EC2AMAZ-GG97ZL$'@CONTOSO.COM
    std::transform( result.second.begin(), result.second.end(),
                    result.second.begin(),
                    []( unsigned char c ) { return std::toupper( c ); } );
    std::string kinit_cmd = "kinit -kt /etc/krb5.keytab '" + result.second + "'";
    result = exec_shell_cmd( kinit_cmd );

    return result.first;
}

/**
 * Replace certain characters that do not have mappings in UTF-16
 * @param input_blob_buf - Buffer from ldap query
 * @param input_blob_buf_sz - size of buffer
 * @return - returns 0 if successful, -1 on error
 */
static int fixup_utf16( uint8_t* input_blob_buf, int32_t input_blob_buf_sz )
{
    if ( input_blob_buf == nullptr || input_blob_buf_sz == 0 )
    {
        return -1;
    }

    /**
     * In UTF-16, characters in ranges U+0000—U+D7FF and U+E000—U+FFFD are
     * stored as a single 16 bits unit.
     */
    auto codepoints = (uint16_t*)input_blob_buf;
    for ( int i = 0; i < input_blob_buf_sz; i++ )
    {
        /**
         * U+D800 to U+DFFF As per, https://en.wikipedia.org/wiki/UTF-16, the
         * Unicode standard permanently reserves these code point values for
         * UTF-16 encoding of the high and low surrogates, and they will never be
         * assigned a character, so there should be no reason to encode them. The
         * official Unicode standard says that no UTF forms, including UTF-16,
         * can encode these code points.
         * For example: (0xdef0 -> 0xfffd) (0xde6f -> 0xfffd)
         *              (0xd82d -> 0xfffd) (0xda34 -> 0xfffd)
         **/
        if ( ( codepoints[i] & 0xf800 ) == 0xd800 )
        {
            codepoints[i] = 0xfffd;
        }
    }
    return 0;
}

/**
 * base64_decode - Decodes base64 encoded string
 * @param password - base64 encoded password
 * @param base64_decode_len - Length after decode
 * @return buffer with base64 decoded contents
 */
static uint8_t* base64_decode( const std::string& password, gsize* base64_decode_len )
{
    if ( base64_decode_len == nullptr || password.empty() )
    {
        return nullptr;
    }

    guchar* result = g_base64_decode( password.c_str(), base64_decode_len );

    /**
     * result must be freed later
     */
    return (uint8_t*)result;
}

/**
 * This function fetches the gmsa password and creates a krb ticket
 * It uses the existing krb ticket of machine to run ldap query over
 * kerberos and do the appropriate UTF decoding.
 *
 * @param domain_name - Like 'contoso.com'
 * @param gmsa_account_name - Like 'webapp01'
 * @param krb_cc_name - Like '/tmp/krb5_cc'
 * @param cf_logger - log to systemd daemon
 * @param cf_daemon - parent creds-fetcher object
 * @return result code, 0 if successful, -1 on failure
 */
int get_gmsa_krb_ticket( std::string domain_name, const std::string& gmsa_account_name,
                         const std::string& krb_cc_name, const std::string& krb_files_dir,
                         creds_fetcher::CF_logger& cf_logger)
{
    if ( domain_name.empty() || gmsa_account_name.empty() )
    {
        cf_logger.logger( LOG_ERR, "ERROR*: %s:%d null args", __func__, __LINE__ );
        return -1;
    }

    std::vector<std::string> results;

    boost::split( results, domain_name, []( char c ) { return c == '.'; } );
    std::string domain;
    for ( auto& result : results )
    {
        domain += "DC=" + result + ",";
    }
    domain.pop_back(); // Remove last comma

    /**
     * ldapsearch -H ldap://contoso.com -b 'CN=webapp01,CN=Managed Service
     *   Accounts,DC=contoso,DC=com' -s sub  "(objectClass=msDs-GroupManagedServiceAccount)"
     *   msDS-ManagedPassword
     */
    std::string cmd = std::string( "ldapsearch -H ldap://" ) + domain_name;
    cmd += std::string( " -b 'CN=" ) + gmsa_account_name +
           std::string( ",CN=Managed Service Accounts," ) + domain + std::string( "'" ) +
           std::string( " -s sub  \"(objectClass=msDs-GroupManagedServiceAccount)\" "
                        " msDS-ManagedPassword" );

    std::pair<int, std::string> ldap_search_result = exec_shell_cmd( cmd );
    if ( ldap_search_result.first != 0 )
    {
        cf_logger.logger( LOG_ERR, "ERROR*: %s:%d ldapsearch failed", __func__, __LINE__ );
        return -1;
    }

    std::string password = std::string( "msDS-ManagedPassword::" );
    boost::split( results, ldap_search_result.second, []( char c ) { return c == '#'; } );

    for ( auto& result : results )
    {
        auto found = result.find( password );
        if ( found != std::string::npos )
        {
            found += password.length();
            password = result.substr( found + 1, result.length() );
            break;
        }
    }

    size_t base64_decode_len;
    uint8_t* blob_base64_decoded = base64_decode( password, &base64_decode_len );
    creds_fetcher::blob_t* blob = ( (creds_fetcher::blob_t*)blob_base64_decoded );

    if ( fixup_utf16( blob->buf, BLOB_REMAINING_BUF_SIZE ) < 0 )
    {
        cf_logger.logger( LOG_ERR, "ERROR*: %s:%d utf16 decode failed", __func__, __LINE__ );
        return -1;
    }

    auto* blob_password = (uint8_t *)blob->buf;
    std::string gmsa_password_file = krb_files_dir + std::string( "/gmsa_XXXXXX" );
    // XXXXXX as per mkstemp man page
    char gmsa_password_file_str[PATH_MAX];
    strncpy(gmsa_password_file_str, gmsa_password_file.c_str(), gmsa_password_file.length());
    if ( mkstemp( (char*)gmsa_password_file_str ) < 0 )
    {
        cf_logger.logger( LOG_ERR, "ERROR*: %s:%d mkstemp failed", __func__, __LINE__ );
        free( blob_base64_decoded );
        return -1;
    }
    FILE* fp = fopen( gmsa_password_file_str, "wb" );
    for ( int i = 0; i < GMSA_PASSWORD_SIZE; i++ )
    {
        fprintf( fp, "%c", blob_password[i] );
    }
    fclose( fp );

    std::transform( domain_name.begin(), domain_name.end(), domain_name.begin(),
                    []( unsigned char c ) { return std::toupper( c ); } );
    std::string default_principal = gmsa_account_name + "$@" + domain_name;
    std::string kinit_cmd = std::string("export KRB5CCNAME=") + krb_cc_name + std::string(";") +
                            std::string( " cat " ) +  gmsa_password_file_str +
                            std::string( " | iconv -f utf-16 -t utf-8 | kinit -V '" ) +
                            default_principal + "'";
    std::pair<int, std::string> result = exec_shell_cmd( kinit_cmd );
    if ( result.first != 0 )
    {
        unlink( gmsa_password_file_str );
        cf_logger.logger( LOG_ERR, "ERROR*: %s:%d kinit failed", __func__, __LINE__ );
        free( blob_base64_decoded );
        return result.first;
    }

    unlink( gmsa_password_file_str );
    free( blob_base64_decoded );

    return result.first;
}

/**
 * This function does the ticket renewal.
 * TBD:: update the in memory db about the status of the ticket.
 * @param principal
 * @param krb_ccname
 */
void krb_ticket_renewal( std::string principal, const std::string& krb_ccname )
{
    std::string set_krb_ccname_cmd;

    // set krb cache location krb5ccname
    if ( not krb_ccname.empty() )
    {
        set_krb_ccname_cmd = std::string( "export KRB5CCNAME=" ) + krb_ccname;
    }

    std::string krb_ticket_refresh =
        set_krb_ccname_cmd + " && " + std::string( "kinit -R " ) + std::string( std::move(principal) );

    // TBD: replace with exec_shell_cmd()
    system( krb_ticket_refresh.c_str() );

    // TBD: Add error handling
}
