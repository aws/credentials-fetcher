#ifndef _cache_h_
#define _cache_h_

namespace creds_fetcher{
public class Cache{
    public:
        sqlite3 *db;
        char *errMsg = 0;
        int read_connection;
        /*string lease_id,
        string krb_file_path;
        string service_account_name;
        string domain;
        string time_stamp;*/
    };
}
void initialize_cache(creds_fetcher::Cache cf_cache);
#endif // _cache_h_