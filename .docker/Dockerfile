# This super old image is required to verify cve-2016-3427
FROM tomcat:8.0.37-alpine

# If you want to test on a newer image, you should use the following line instead
#FROM tomcat:9-alpine

# Copy authentication and cert files
COPY ./resources/trust/store.p12 /opt/store.p12
COPY ./resources/conf/jmxmp.access /opt/jmxmp.access
COPY ./resources/conf/jmxremote.access /opt/jmxremote.access
COPY ./resources/conf/jmxremote.password /opt/jmxremote.password

# Copy server configuration files
COPY ./resources/conf/server.xml /usr/local/tomcat/conf/server.xml
COPY ./resources/conf/tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
COPY ./resources/conf/context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml

# Copy additional jars
COPY ./resources/jmxmp.jar /usr/local/tomcat/lib/jmxmp.jar
COPY ./resources/jmxremote-optional.jar /usr/local/tomcat/lib/jmxremote-optional.jar
COPY ./resources/commons-collections-3.1.jar /usr/local/tomcat/lib/commons-collections-3.1.jar

CMD ["catalina.sh", "run"]
