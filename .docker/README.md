### Docker Container

----

If you want to test *jmx-exploiter*, you can do this using the docker container provided in this repository.
The *docker-compose.yml* file in this folder builds a docker container based on the *tomcat9-alpine* image.
The server has JMX enabled and also provides a JMXMP listener.


### Configuration Details

-----

```java
-Dcom.sun.management.jmxremote
-Dcom.sun.management.jmxremote.local.only=false
-Dcom.sun.management.jmxremote.authenticate=false
-Dcom.sun.management.jmxremote.port=9010
-Dcom.sun.management.jmxremote.rmi.port=9011
-Dcom.sun.management.jmxremote.ssl=true
-Dcom.sun.management.jmxremote.registry.ssl=true
-Djava.rmi.server.hostname=iinsecure.dev
-Djavax.net.ssl.keyStore=/opt/store.p12
-Djavax.net.ssl.keyStorePassword=password
-Djavax.net.ssl.keyStoreType=pkcs12
```

By default, the container uses *SSL* on both, the registry and for *RMI* connections. The corresponding hostname is
``iinsecure.dev`` and should be added to your ``/etc/hosts`` file for testing. The JMXMP listener will start on
port 5555.

Notice that the **docker-compose.yml** file does not map any container ports to your docker host system. Therfore, you
have to target the IP address of the docker container directly to connect to the exposed services.


### Some Test Cases

-----

In the following, some example test cases and the behavior of ``jmx-exploiter`` are shown.


#### SSL Protected Registry

After starting the container using ``docker-compose up`` you can test ``jmx-exploiter``. As *SSL* is enabled by
default for the *RMI registry*, running ``jmx-exploiter`` without the ``--ssl`` option will fail:

```console
[qtc@kali jmx-exploiter]$ jmx-exploiter 172.30.0.2 9010 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.io.IOException: Failed to retrieve RMIServer stub: javax.naming.CommunicationException [Root exception is java.rmi.ConnectIOException: non-JRMP server at remote endpoint]
```

Running with the ``--ssl`` option should work fine:

```console
[qtc@kali jmx-exploiter]$ jmx-exploiter --ssl 172.30.0.2 9010 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```
