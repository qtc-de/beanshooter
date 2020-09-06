FROM tomcat:9-alpine

# Install required packages
RUN set -ex \
    && apk update \
    && apk add git \
    && apk add maven \
    && apk add openjdk8

# Copy required files
COPY ./resources/src/jmxmp /opt/jmxmp
COPY ./resources/trust/store.p12 /opt/store.p12
COPY ./resources/conf/jmxremote.password /opt/jmxremote.password
COPY ./resources/conf/jmxremote.access /opt/jmxremote.access
COPY ./resources/conf/server.xml /usr/local/tomcat/conf/server.xml
COPY ./resources/conf/tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
COPY ./resources/conf/context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml
COPY ./resources/jmxremote-optional.jar /usr/local/tomcat/lib/jmxremote-optional.jar

# Build JMXMP listener
RUN set -ex \
    && cd /opt/jmxmp && mvn clean package \
    && cp /opt/jmxmp/target/jmxmp-1.0.0.jar $CATALINA_HOME/lib/jmxmp.jar \
    && cd -

# Start tomcat as usual
CMD ["catalina.sh", "run"]
