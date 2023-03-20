###########################################
###            Build Stage 1            ###
###########################################
FROM maven:3.8.6-openjdk-8-slim AS maven-builder
COPY ./pom.xml /usr/src/app/pom.xml
COPY ./beanshooter /usr/src/app/beanshooter
COPY ./tonka-bean /usr/src/app/tonka-bean
WORKDIR /usr/src/app
RUN mvn clean package

###########################################
###            Build Stage 2            ###
###########################################
FROM alpine:latest AS jdk-builder
RUN set -ex \
    && apk add --no-cache openjdk11 \
    && /usr/lib/jvm/java-11-openjdk/bin/jlink \
       --add-modules java.desktop,java.management.rmi,jdk.naming.rmi,java.security.sasl,jdk.unsupported,jdk.httpserver,java.xml \
       --verbose --strip-debug --compress 2 --no-header-files --no-man-pages --output /jdk

###########################################
###          Container Stage            ###
###########################################
FROM alpine:latest

COPY --from=maven-builder /usr/src/app/target/beanshooter-*-jar-with-dependencies.jar /opt/beanshooter.jar
COPY --from=jdk-builder /jdk /usr/lib/jvm/java-11-openjdk

RUN set -ex \
    && ln -s /usr/lib/jvm/java-11-openjdk/bin/java /usr/bin/java \
    && adduser -g '' -D -u 1000 beanshooter-user                 \
    && wget -O /opt/yso.jar https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar

USER beanshooter-user:beanshooter-user

ENTRYPOINT ["java", "-jar", "/opt/beanshooter.jar"]
