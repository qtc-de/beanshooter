###########################################
###             Build Stage             ###
###########################################
FROM maven:3.6.3-openjdk-16-slim AS builder
COPY ./resources/jmxmp /usr/src/app
WORKDIR /usr/src/app
RUN mvn clean package


###########################################
###          Container Stage            ###
###########################################
FROM tomcat:8.0.18-jre8
ENV SHA256_SUM c1547d185ba6880bcc2da261c5f7533512b6ffdbbc1898db5b793c0cb830fcf0

COPY ./resources/conf/tomcat-users.xml ./resources/conf/server.xml /usr/local/tomcat/conf/
COPY ./resources/conf/context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml
COPY ./resources/trust/store.p12 /opt/store.p12
COPY ./resources/scripts/start.sh /opt/start.sh
COPY ./resources/conf/jmx* /opt/

COPY --from=builder /usr/src/app/target/jmxmp-*-jar-with-dependencies.jar /usr/local/tomcat/lib/jmxmp.jar

RUN set -ex \
    && chmod 400 /opt/jmxmp.access /opt/jmxremote.access /opt/jmxremote.password \
    && chmod 774 /opt/start.sh \
    && cd /usr/lib/jvm/java-8-openjdk-amd64/jre/lib/ext/ \
    && wget https://repo1.maven.org/maven2/commons-collections/commons-collections/3.1/commons-collections-3.1.jar \
    && if [ "$SHA256_SUM" != "$(sha256sum commons-collections-3.1.jar | awk '{print($1)}')" ]; then \
           echo "sha512 values doesn't match! exiting." \
           && exit 1; \
       fi \
    && cd -

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

CMD ["/opt/start.sh"]
