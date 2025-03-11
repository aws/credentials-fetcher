import java.sql.*;

public class SQLServerKerberosConnection {
    public static void main(String[] args) {

        System.setProperty("java.security.krb5.principal", args[2] + "@" + args[1]);

        String connectionUrl = "jdbc:sqlserver://" + args[0] + ":1433;"
                + "databaseName=EmployeesDB;"
                + "integratedSecurity=true;"
                + "authenticationScheme=JavaKerberos;"
                + "userName=" + args[2] + "@" + args[1] + ";"
                + "serverSpn=MSSQLSvc/" + args[0] + ":1433;"
                + "trustServerCertificate=true";

        try {
            // Ensure the JDBC driver is loaded
            Class.forName("com.microsoft.sqlserver.jdbc.SQLServerDriver");

            // Establish the connection
            try (Connection connection = DriverManager.getConnection(connectionUrl)) {
                System.out.println("Connected successfully using Kerberos authentication.");

                // Perform a simple query
                try (Statement statement = connection.createStatement();
                     ResultSet resultSet = statement.executeQuery("SELECT * from EmployeesDB.dbo.EmployeesTable")) {
                    
                    ResultSetMetaData metaData = resultSet.getMetaData();
                    int columnCount = metaData.getColumnCount();

                    String[] columns = new String[columnCount];
                    for (int i = 0; i < columnCount; i++) {
                        columns[i] = metaData.getColumnName(i + 1);
                    }
                    printRow(columns);

                    // Display data rows
                    while (resultSet.next()) {
                        String[] row = new String[columnCount];
                        for (int i = 0; i < columnCount; i++) {
                            row[i] = resultSet.getString(i + 1);
                        }
                        printRow(row);
                    }
                }
            }
        } catch (ClassNotFoundException e) {
            System.err.println("Error loading JDBC driver: " + e.getMessage());
        } catch (SQLException e) {
            System.err.println("Error connecting to the database: " + e.getMessage());
        }
    }


    private static void printRow(String[] row) {
        System.out.println("+---------------------------".repeat(row.length) + "+");
        for (String col : row) {
            System.out.printf("| %-25s ", col != null ? col : "NULL");
        }
        System.out.println("|");
    }
}
