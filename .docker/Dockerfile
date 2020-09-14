# This old image is required to verify cve-2016-3427
FROM tomcat:8.0.37-alpine

# If you want to test on a newer image, you should use the following line instead
# You can also use the Dockerfile.alternative
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
COPY ./resources/commons-collections-3.1.jar /usr/lib/jvm/java-1.7-openjdk/jre/lib/ext/commons-collections-3.1.jar

# Setup the environment (ssl registry, ssl jmx, no auth)
ENV CATALINA_OPTS -Dcom.sun.management.jmxremote \
    -Dcom.sun.management.jmxremote.local.only=false \
    -Dcom.sun.management.jmxremote.authenticate=false \
    -Dcom.sun.management.jmxremote.port=9010 \
    -Dcom.sun.management.jmxremote.rmi.port=9011 \
    -Djava.rmi.server.hostname=iinsecure.dev \
    -Djavax.net.ssl.keyStorePassword=password \
    -Djavax.net.ssl.keyStore=/opt/store.p12 \
    -Djavax.net.ssl.keyStoreType=pkcs12 \
    -Dcom.sun.management.jmxremote.ssl=true \
    -Dcom.sun.management.jmxremote.registry.ssl=true

CMD ["catalina.sh", "run"]
