### JMX Example Server

----

The *JMX example server* is a docker container that runs several differently configured *JMX*
endpoints. It can be used to practice and test almost all actions supported by *beanshooter*.


### Service Summary

----

Here is a summarized overview of the exposed services:


* ``0.0.0.0:1090`` - *RMI registry* binding a *JMX remote object* that requires authentication
* ``0.0.0.0:1099`` - *SSL* protected *RMI registry* binding a *JMX remote object* that requires authentication
* ``0.0.0.0:4444`` - *JMXMP* endpoint without *SASL*
* ``0.0.0.0:4445`` - *JMXMP* endpoint with `TLS` *SASL* profile
* ``0.0.0.0:4446`` - *JMXMP* endpoint with `TLS PLAIN` *SASL* profile
* ``0.0.0.0:4447`` - *JMXMP* endpoint with `TLS DIGEST-MD5` *SASL* profile
* ``0.0.0.0:4448`` - *JMXMP* endpoint with `TLS CRAM-MD5` *SASL* profile
* ``0.0.0.0:4449`` - *JMXMP* endpoint with `TLS NTLM` *SASL* profile
* ``0.0.0.0:9010`` - *RMI registry* binding a *JMX remote object* that does not require authentication


### Credentials

----

* All *JMXMP* endpoints that require authentication (`4446-4449`) and the
  *JMX* service listening on `1099` use the following credentials:
  * `controlRole:control`
  * `monitorRole:monitor`

* The password protected *JMX* service on port `1090` uses the following credentials:
  * `admin:admin`

