FROM openjdk:11-oracle

RUN microdnf install krb5-workstation unzip wget -y
RUN microdnf clean all

WORKDIR /app

COPY mssql-jdbc-12.8.1.jre8.jar /app/

# Copy your Java file
COPY SQLServerKerberosConnection.java /app/

# Compile with JDBC driver in classpath
RUN javac -cp "/app/mssql-jdbc-12.8.1.jre8.jar" SQLServerKerberosConnection.java

ENV LEASE_ID="default"

ENV SERVER_NAME=default_server \
    DOMAIN_NAME=default_domain \
    USER_NAME=default_user

# Run the Java program with parameters
CMD ["sh", "-c", "export KRB5CCNAME=/var/credentials-fetcher/krbdir/${LEASE_ID}/WebApp01/krb5cc && echo \"Using KRB5CCNAME: $KRB5CCNAME\" && klist && java -cp '.:/app/mssql-jdbc-12.8.1.jre8.jar' SQLServerKerberosConnection ${SERVER_NAME} ${DOMAIN_NAME} ${USER_NAME}"]
