FROM tomcat:9.0.58-jre11-openjdk-slim

COPY ./resources/trust/store.p12            \
     ./resources/scripts/start.sh           \
     /opt/

COPY ./resources/conf/tomcat-users.xml      \
     /usr/local/tomcat/conf/tomcat-users.xml

RUN set -ex \
    && chmod +x /opt/start.sh

ENV _JAVA_OPTIONS -Djava.rmi.server.hostname=iinsecure.dev \
    -Djavax.net.ssl.keyStorePassword=password \
    -Djavax.net.ssl.keyStore=/opt/store.p12 \
    -Djavax.net.ssl.keyStoreType=pkcs12 \
    -Dcom.sun.management.jmxremote \
    -Dcom.sun.management.jmxremote.ssl=false \
    -Dcom.sun.management.jmxremote.local.only=false \
    -Dcom.sun.management.jmxremote.authenticate=false \
    -Dcom.sun.management.jmxremote.port=1090 \
    -Dcom.sun.management.jmxremote.rmi.port=1099

EXPOSE 1090/tcp 1099/tcp 8080/tcp

CMD ["/opt/start.sh"]
