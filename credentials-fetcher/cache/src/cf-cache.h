#ifndef _cf_cache_h_
#define _cf_cache_h_

namespace creds_fetcher{

class CF_cache{
    public:
        sqlite3 *db;
        char *errMsg = 0;
        int read_connection;
        std::string sql;
        std::list<creds_fetcher::krb_ticket_info> *krb_ticket_infos = new std::list<creds_fetcher::krb_ticket_info>;
    };
}
void initialize_cache(creds_fetcher::CF_cache &cf_cache);
#endif // _cf_cache_h_