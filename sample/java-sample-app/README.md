# SQL Server Kerberos Authentication Java Application

A simple Java application that connects to Microsoft SQL Server using Kerberos authentication and executes a simple Select command on the database.

## Prerequisites

- Microsoft JDBC Driver for SQL Server (JDBC driver used to create this app is ```mssql-jdbc-12.8.1.jre8.jar```)
- Valid Kerberos ticket (can be verified using `klist`)
- SQL Server configured for Kerberos authentication

## Files Required

1. `SQLServerKerberosConnection.class` - The compiled Java class file
2. `mssql-jdbc-12.8.1.jre8.jar` - Microsoft JDBC driver for SQL Server
3. `Dockerfile ` - The Dockerfile in this directory

## Environment Setup

1. Ensure you have a valid Kerberos ticket:
```
klist
```

2. Build the dockerfile 
```
docker build -t myjava .
```

3. Run the docker container
```
docker run -it \
    -e LEASE_ID=<lease_id> \
    -e SERVER_NAME=<server_name> (example: EC2AMAZ-938NTBH.contoso.com) \
    -e DOMAIN_NAME=<domain_name> (example: CONTOSO.COM) \
    -e USER_NAME=<user_name> (example: standarduser01) \
    -v /var/credentials-fetcher/krbdir:/var/credentials-fetcher/krbdir \
    -v /etc/krb5.conf:/etc/krb5.conf:ro \
    myjava
```

4. You should see the following output
```
Using KRB5CCNAME: /var/credentials-fetcher/krbdir/49ccb67e16ba17c4f14f/WebApp01/krb5cc
Ticket cache: FILE:/var/credentials-fetcher/krbdir/49ccb67e16ba17c4f14f/WebApp01/krb5cc
Default principal: WebApp01$@CONTOSO.COM

Valid starting     Expires            Service principal
02/07/25 22:36:38  02/08/25 08:36:38  krbtgt/CONTOSO.COM@CONTOSO.COM
        renew until 02/14/25 22:36:37
Connected successfully using Kerberos authentication.
+---------------------------+---------------------------+---------------------------+---------------------------+---------------------------+
| EmpID                     | EmpName                   | Designation               | Department                | JoiningDate               |
+---------------------------+---------------------------+---------------------------+---------------------------+---------------------------+
| 1                         | CHIN YEN                  | LAB ASSISTANT             | LAB                       | 2022-03-05 03:57:09.967   |
+---------------------------+---------------------------+---------------------------+---------------------------+---------------------------+
| 2                         | MIKE PEARL                | SENIOR ACCOUNTANT         | ACCOUNTS                  | 2022-03-05 03:57:09.967   |
+---------------------------+---------------------------+---------------------------+---------------------------+---------------------------+
| 3                         | GREEN FIELD               | ACCOUNTANT                | ACCOUNTS                  | 2022-03-05 03:57:09.967   |
+---------------------------+---------------------------+---------------------------+---------------------------+---------------------------+
| 4                         | DEWANE PAUL               | PROGRAMMER                | IT                        | 2022-03-05 03:57:09.967   |
+---------------------------+---------------------------+---------------------------+---------------------------+---------------------------+
| 5                         | MATTS                     | SR. PROGRAMMER            | IT                        | 2022-03-05 03:57:09.967   |
+---------------------------+---------------------------+---------------------------+---------------------------+---------------------------+
| 6                         | PLANK OTO                 | ACCOUNTANT                | ACCOUNTS                  | 2022-03-05 03:57:09.967   |
```