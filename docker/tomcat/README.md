### JMX Example Server

----

The *tomcat example server* is a docker container that runs an *Apache tomcat service* that exposes
one *JMX* endpoint. It can be used to practice and test the *tomcat* related operations of *beanshooter*.


### Service Summary

----

Here is a summarized overview of the exposed services:


* ``0.0.0.0:1090`` - *RMI registry* containing the bound name for the *JMX* service
* ``0.0.0.0:1099`` - The actual *JMX RMI* port, where the remote object is listening
* ``0.0.0.0:8080`` - Ordinary *tomcat HTTP service*


### Example Usage

----

The following listing shows a short example, where *beanshooters* `enum` action was used against
the *JMX* endpoint:

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
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Mapper)
[+] 	  - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="admin-gui",database=UserDatabase)
[+] 	  - org.apache.catalina.mbeans.NamingResourcesMBean (Catalina:type=NamingResources)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,name=StandardHostValve)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Realm,realmPath=/realm0/realm0)
[+] 	  - org.apache.catalina.mbeans.ServiceMBean (Catalina:type=Service)
[+] 	  - com.sun.management.internal.GarbageCollectorExtImpl (java.lang:name=G1 Young Generation,type=GarbageCollector)
[+] 	  - com.sun.management.internal.HotSpotDiagnostic (com.sun.management:type=HotSpotDiagnostic)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=MBeanFactory)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=SocketProperties,name="http-nio-8080")
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=ProtocolHandler,port=8080)
[+] 	  - org.apache.catalina.mbeans.UserMBean (Users:type=User,username="status",database=UserDatabase)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,name=StandardEngineValve)
[+] 	  - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="manager-gui",database=UserDatabase)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Realm,realmPath=/realm0)
[+] 	  - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="manager-jmx",database=UserDatabase)
[+] 	  - com.sun.management.internal.OperatingSystemImpl (java.lang:type=OperatingSystem)
[+] 	  - jdk.management.jfr.FlightRecorderMXBeanImpl (jdk.management.jfr:type=FlightRecorder)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Deployer,host=localhost)
[+] 	  - org.apache.catalina.mbeans.ContextResourceMBean (Catalina:type=Resource,resourcetype=Global,class=org.apache.catalina.UserDatabase,name="UserDatabase")
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Server)
[+] 	  - org.apache.catalina.mbeans.MemoryUserDatabaseMBean (Users:type=UserDatabase,database=UserDatabase)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=UtilityExecutor)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=StringCache)
[+] 	  - org.apache.catalina.mbeans.ConnectorMBean (Catalina:type=Connector,port=8080)
[+] 	  - org.apache.catalina.mbeans.UserMBean (Users:type=User,username="admin",database=UserDatabase)
[+] 	  - org.apache.catalina.mbeans.UserMBean (Users:type=User,username="manager",database=UserDatabase)
[+] 	  - com.sun.management.internal.HotSpotThreadImpl (java.lang:type=Threading)
[+] 	  - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="admin-script",database=UserDatabase)
[+] 	  - org.apache.tomcat.util.modeler.BaseModelMBean (Catalina:type=Valve,host=localhost,name=ErrorReportValve)
[+] 	  - org.apache.catalina.mbeans.ClassNameMBean (Catalina:type=ThreadPool,name="http-nio-8080")
[+] 	  - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="manager-status",database=UserDatabase)
[+] 	  - org.apache.catalina.mbeans.ContainerMBean (Catalina:type=Host,host=localhost)
[+] 	  - org.apache.catalina.mbeans.RoleMBean (Users:type=Role,rolename="manager-script",database=UserDatabase)
[+] 	  - com.sun.management.internal.DiagnosticCommandImpl (com.sun.management:type=DiagnosticCommand)
[+] 	  - com.sun.management.internal.GarbageCollectorExtImpl (java.lang:name=G1 Old Generation,type=GarbageCollector)
[+] 	  - org.apache.catalina.mbeans.ContainerMBean (Catalina:type=Engine)
[+]
[+] Enumerating tomcat users:
[+]
[+] 	- Listing 3 tomcat users:
[+]
[+] 		----------------------------------------
[+] 		Username:       manager
[+] 		Password:		P@55w0rD#
[+] 		Roles:
[+] 			Users:type=Role,rolename="manager-gui",database=UserDatabase
[+] 			Users:type=Role,rolename="manager-script",database=UserDatabase
[+] 			Users:type=Role,rolename="manager-jmx",database=UserDatabase
[+] 			Users:type=Role,rolename="manager-status",database=UserDatabase
[+]
[+] 		----------------------------------------
[+] 		Username:		admin
[+] 		Password:		s3cr3T!$
[+] 		Roles:
[+] 			Users:type=Role,rolename="admin-gui",database=UserDatabase
[+] 			Users:type=Role,rolename="admin-script",database=UserDatabase
[+]
[+] 		----------------------------------------
[+] 		Username:		status
[+] 		Password:		cr@cKM3o.O
[+] 		Roles:
[+] 			Users:type=Role,rolename="manager-status",database=UserDatabase
```
