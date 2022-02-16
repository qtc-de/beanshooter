###########################################
###            Build Stage 1            ###
###########################################
FROM maven:3.8.2-openjdk-8 AS maven-builder
COPY ./resources/server /usr/src/app
WORKDIR /usr/src/app
RUN mvn clean package

###########################################
###            Build Stage 2            ###
###########################################
FROM alpine:latest AS jdk-builder
RUN set -ex \
    && apk add --no-cache openjdk11 \
    && /usr/lib/jvm/java-11-openjdk/bin/jlink --add-modules java.rmi,java.management.rmi,jdk.management.agent,jdk.naming.rmi --verbose --strip-debug --compress 2 \
       --no-header-files --no-man-pages --output /jdk

###########################################
###          Container Stage            ###
###########################################
FROM alpine:latest

COPY ./resources/trust/store.p12            \
     ./resources/scripts/start.sh           \
     ./resources/conf/jmxmp.access          \
     ./resources/conf/jmxremote.access      \
     ./resources/conf/jmxremote.password    \
     /opt/

COPY --from=maven-builder /usr/src/app/target/jmx-example-server*-jar-with-dependencies.jar /opt/jmx-example-server.jar
COPY --from=jdk-builder /jdk /usr/lib/jvm/java-11-openjdk

RUN set -ex \
    && ln -s /usr/lib/jvm/java-11-openjdk/bin/java /usr/bin/java \
    && chmod 400 /opt/jmxmp.access \
    && chmod 400 /opt/jmxremote.access \
    && chmod 400 /opt/jmxremote.password \
    && chmod +x /opt/start.sh

ENV _JAVA_OPTIONS -Djava.rmi.server.hostname=iinsecure.dev \
    -Djavax.net.ssl.keyStorePassword=password \
    -Djavax.net.ssl.keyStore=/opt/store.p12 \
    -Djavax.net.ssl.keyStoreType=pkcs12 \
    -Dcom.sun.management.jmxremote \
    -Dcom.sun.management.jmxremote.local.only=false \
    -Dcom.sun.management.jmxremote.authenticate=true \
    -Dcom.sun.management.jmxremote.port=1099 \
    -Dcom.sun.management.jmxremote.rmi.port=1099 \
    -Dcom.sun.management.jmxremote.ssl=true \
    -Dcom.sun.management.jmxremote.registry.ssl=true \
    -Dcom.sun.management.jmxremote.password.file=/opt/jmxremote.password \
    -Dcom.sun.management.jmxremote.access.file=/opt/jmxremote.access

EXPOSE 1090/tcp 1099/tcp 4444/tcp 4445/tcp 4446/tcp 4447/tcp 4448/tcp 4449/tcp 9010/tcp

CMD ["/opt/start.sh"]
