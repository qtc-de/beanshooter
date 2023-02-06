FROM tomcat:9-jdk8

COPY ./resources/conf/tomcat-users.xml      \
     ./resources/conf/jmxremote.access      \
     ./resources/conf/jmxremote.password    \
     ./resources/scripts/start.sh           \
     /usr/local/tomcat/conf/

RUN set -ex \
    && chmod 400 /usr/local/tomcat/conf/jmxremote.access    \
    && chmod 400 /usr/local/tomcat/conf/jmxremote.password  \
    && chmod +x /usr/local/tomcat/conf/start.sh             \
    && wget -O /usr/local/tomcat/webapps/jolokia.war        \
       'https://search.maven.org/remotecontent?filepath=org/jolokia/jolokia-war/1.7.1/jolokia-war-1.7.1.war'

ENV _JAVA_OPTIONS -Djava.rmi.server.hostname=localhost \
    -Dcom.sun.management.jmxremote \
    -Dcom.sun.management.jmxremote.ssl=false \
    -Dcom.sun.management.jmxremote.local.only=true \
    -Dcom.sun.management.jmxremote.authenticate=false \
    -Dcom.sun.management.jmxremote.port=1090 \
    -Dcom.sun.management.jmxremote.rmi.port=1090 \
    -Dcom.sun.management.jmxremote.password.file=/usr/local/tomcat/conf/jmxremote.password \
    -Dcom.sun.management.jmxremote.access.file=/usr/local/tomcat/conf/jmxremote.access \
    -Dorg.jolokia.jsr160ProxyEnabled=true

EXPOSE 1090/tcp 8080/tcp

CMD ["/usr/local/tomcat/conf/start.sh"]
