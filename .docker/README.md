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
``iinsecure.dev`` and should be added to your ``/etc/hosts`` file for testing.

* *RMI Registry*: ``Port 9010 - SSL Protected``
* *JMX Access*: ``Port 9011 - SSL Protected``

Additionally, the container opens 5 *JMXMP* listeners:

* *JMXMP PLAIN*: ``Port 5555``
* *JMXMP TLS*: ``Port 5556 - TLS Protected``
* *JMXMP TLS SASL/PLAIN*: ``Port 5557 - TLS Protected & SASL PLAIN auth``
* *JMXMP TLS SASL/Digest*: ``Port 5558 - TLS Protected & SASL Digest auth``
* *JMXMP TLS SASL/Cram*: ``Port 5559 - TLS Protected & SASL Cram auth``
* *JMXMP TLS SASL/NTLM*: ``Port 5560 - TLS Protected & SASL NTLM auth``

Notice that the **docker-compose.yml** file does not map any container ports to your host system. Therefore, you
have to target the IP address of the docker container directly to connect to the exposed services.

The container does not define any security policy for *JMX*. Therefore, when used with authentication, certain operations
like creating new *mBeans* on the server probably do not work.


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

#### JMXMP

The following example shows a simple connection to the *JMXMP* port:

```console
[qtc@kali jmx-exploiter]$ jmx-exploiter --jmxmp 172.30.0.2 5555 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```

#### JMXMP - SSL

Now the *JMXMP* listener is *SSL protected*. First of all, notice how ``nmap`` flags
this port:

```console
[qtc@kali jmx-exploiter]$ nmap -p 5556 172.30.0.2 -sV
[...]

PORT     STATE SERVICE     VERSION
5556/tcp open  java-object Java Object Serialization
```

Just connecting without *SSL* will lead to the following error:

```console
[qtc@kali jmx-exploiter]$ jmx-exploiter --jmxmp 172.30.0.2 5556 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.io.IOException: The client does not require any profile but the server mandates one
```

This is because with *JMXMP* additional protection mechanisms have to be specified as a *profile string* like e.g. *TLS SASL/PLAIN*.
By using the ``--ssl`` option, the connection should work fine:

```console
[qtc@kali jmx-exploiter]$ jmx-exploiter --jmxmp --ssl 172.30.0.2 5556 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```

#### JMXMP - SASL/NTLM

Now lets take a look on a *SASL* protected *JMXMP* endpoint that uses *NTLM* and *TLS* protection. ``nmap`` flags this again as ``Java Object Serialization``
and connection without the appropriate options creates the following error:

```console
[qtc@kali jmx-exploiter]$ jmx-exploiter --jmxmp --ssl 172.30.0.2 5560 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.io.IOException: The server supported profiles [SASL/NTLM] do not match the client required profiles [TLS].
```

This is nice, as the server informs us about the required connection profile. Retrying the connection with the correct options but wrong credentials looks
like this:

```console
[qtc@kali jmx-exploiter]$ jmx-exploiter --jmxmp --sasl NTLM --username test --password test 172.30.0.2 5560 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.lang.SecurityException: javax.security.sasl.SaslException: NTLM: generate response failure [Caused by com.sun.security.ntlm.NTLMException: None of LM and NTLM verified]
```

However, when using the correct credentials, the connection should work again:

```console
[qtc@kali jmx-exploiter]$ jmx-exploiter --jmxmp --sasl NTLM --username controlRole --password control 172.30.0.2 5560 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```

#### JMXMP - SASL/Digest

One special case is *Digest* authentication (at least for the container provided in this project). Unfortunately, the ``com.sun.security.sasl.digest.realm`` property
is ignored by the ``LifecycleListener`` and therefore the hostname of the container is used as the realm for the *Digest authentication*. This leads to the following
error message when using *Digest authentication*:

```console
[qtc@kali jmx-exploiter]$ jmx-exploiter --jmxmp --sasl DIGEST-MD5 --username controlRole --password control 172.30.0.2 5558 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.lang.SecurityException: javax.security.sasl.SaslException: DIGEST-MD5: digest response format violation. Mismatched URI: jmxmp/iinsecure.dev; expecting: jmxmp/4839abafde05
```

With a correct configured server, this should not happen. However, one can easily fix that as the server exposes the correct hostname as part of the error message. By adding it to the ``/etc/hosts`` file the
connection should work again:

```console
[qtc@kali jmx-exploiter]$ head -n 1 /etc/hosts
172.30.0.2  4839abafde05
[qtc@kali jmx-exploiter]$ jmx-exploiter --jmxmp --sasl DIGEST-MD5 --username controlRole --password control 172.30.0.2 5558 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```
