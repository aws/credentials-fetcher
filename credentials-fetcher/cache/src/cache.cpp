#include "daemon.h"

int callback(void *pObject, int columns, char **columnValues, char **columnNames) {
   int i;
   for(i = 0; i < columns; i++) {
      printf("%s = %s\n", columnNames[i], columnValues[i] ? columnValues[i] : "NULL");
   }
   printf("\n");
   return 0;
}

void open_database_connection(creds_fetcher::CF_cache &cf_cache)
{
    // open or create the database
    cf_cache.read_connection = sqlite3_open("credentials-fetcher-cache.db", &cf_cache.db);

    if( cf_cache.read_connection ) {
           fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(cf_cache.db));
             //TBD: return on error, throw error
       } else {
           fprintf(stderr, "Opened database successfully\n");
       }
}

void insert_records_to_cache(creds_fetcher::CF_cache &cf_cache, std::list<creds_fetcher::krb_ticket_info> krb_ticket_infos)
{
   cf_cache.sql = "INSERT INTO krb_cache (lease_id, krb_file_path, service_account_name, domain_name) "
                           "VALUES (1, '/tmp/test1', 'webapp01$', 'contoso.com' ),"
                           "(2, '/tmp/test2', 'webapp02$', 'contoso.com'),"
                           "(3, '/tmp/test3', 'webapp03$', 'contoso.com'),"
                           "(4, '/tmp/test4', 'webapp04$', 'contoso.com');";
   /* Execute SQL statement */
   cf_cache.read_connection  = sqlite3_exec(cf_cache.db, cf_cache.sql.c_str(), callback, 0, &cf_cache.errMsg);

   if( cf_cache.read_connection  != SQLITE_OK ){
          fprintf(stderr, "SQL error: %s\n", cf_cache.errMsg);
         //TBD: return on error, throw error
      } else {
            fprintf(stdout, "Records created successfully\n");
   }
}

void read_records_from_cache(creds_fetcher::CF_cache &cf_cache)
{
    sqlite3_stmt* stmt = 0;

    cf_cache.sql = "SELECT * from krb_cache;";
    /* Execute SQL statement */
    cf_cache.read_connection = sqlite3_prepare_v2( cf_cache.db, cf_cache.sql.c_str(), -1, &stmt, 0 );

    if( cf_cache.read_connection != SQLITE_OK ) {
          fprintf(stderr, "SQL error: %s\n", cf_cache.errMsg);
       } else {
          fprintf(stdout, "Operation done successfully\n");
    }

   // TBD: error handling, not to fail the loop
    while ( sqlite3_step( stmt ) == SQLITE_ROW ) {
        //creds_fetcher::krb_ticket_info krb_ticket_info;

        std::string str = std::string(reinterpret_cast<const char *>(sqlite3_column_text( stmt, 1 )));
       // krb_ticket_info.krb_file_path = std::string(reinterpret_cast<const char *>(sqlite3_column_text( stmt, 1 )));
        //krb_ticket_info.service_account_name =  std::string(reinterpret_cast<const char *>(sqlite3_column_text( stmt, 2 )));
        //krb_ticket_info.domain_name =  std::string(reinterpret_cast<const char *>(sqlite3_column_text( stmt, 3 )));
       // krb_ticket_infos.push_back(krb_ticket_info);
    }
}

void delete_records_from_cache(creds_fetcher::CF_cache &cf_cache)
{
      cf_cache.sql = "DELETE from krb_cache where lease_id = 1";
       /* Execute SQL statement */
       cf_cache.read_connection  = sqlite3_exec(cf_cache.db, cf_cache.sql.c_str(), callback, 0, &cf_cache.errMsg);

       if( cf_cache.read_connection  != SQLITE_OK ){
              fprintf(stderr, "SQL error: %s\n", cf_cache.errMsg);
          } else {
                fprintf(stdout, "Operation done successfully\n");
       }
}

void initialize_cache(creds_fetcher::CF_cache &cf_cache)
{
   open_database_connection(cf_cache);
   // create a sql table if not exits
   cf_cache.sql = "CREATE TABLE IF NOT EXISTS krb_cache("
                            "lease_id                INT    NOT NULL,"
                            "krb_file_path           CHAR   NOT NULL,"
                            "service_account_name    CHAR   NOT NULL,"
                            "domain_name             CHAR   NOT NULL,"
                            "last_updated_time_stamp DATETIME default current_timestamp);";
   /* Execute SQL statement */
   cf_cache.read_connection  = sqlite3_exec(cf_cache.db, cf_cache.sql.c_str(), callback, 0, &cf_cache.errMsg);

   if( cf_cache.read_connection  != SQLITE_OK ){
         fprintf(stderr, "SQL error: %s\n", cf_cache.errMsg);
         //TBD: return on error, throw error
     } else {
         fprintf(stdout, "Table created successfully\n");
     }
     //read_records_from_cache(cf_cache);
    //insert_records_to_cache(cf_cache);
    //delete_records_from_cache(cf_cache);
}





