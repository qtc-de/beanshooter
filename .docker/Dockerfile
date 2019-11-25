FROM tomcat:9-alpine

# Install required packages
RUN set -ex \
    && apk update \
    && apk add git \
    && apk add maven \
    && apk add openjdk8

# Build JMXMP Agent
RUN set -ex \
    && mkdir /opt \
    && git clone https://github.com/nickman/JMXMPAgent /opt/JMXMPAgent \
    && cd /opt/JMXMPAgent/agent && mvn clean package

# Copy local resources
COPY ./resources/tomcat-users.xml /usr/local/tomcat/conf/tomcat-users.xml
COPY ./resources/context.xml /usr/local/tomcat/webapps/manager/META-INF/context.xml
COPY ./resources/start.sh /opt/start.sh

WORKDIR /
RUN chmod +x /opt/start.sh
CMD ["/opt/start.sh"]
