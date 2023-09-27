FROM quay.io/wildfly/wildfly:latest

COPY ./resources/trust/store.p12 /opt/jboss/wildfly/standalone/configuration/application.keystore

RUN /opt/jboss/wildfly/bin/add-user.sh admin admin --silent && \
    sed -i 's/http-interface /http-interface ssl-context="applicationSSC" /' /opt/jboss/wildfly/standalone/configuration/standalone.xml && \
    sed -i '59i <socket-binding https="management-https"/>' /opt/jboss/wildfly/standalone/configuration/standalone.xml

EXPOSE 8080/tcp 8443/tcp 9990/tcp 9993/tcp
CMD ["/opt/jboss/wildfly/bin/standalone.sh", "-b", "0.0.0.0", "-bmanagement", "0.0.0.0"]
