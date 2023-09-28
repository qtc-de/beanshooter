### JBoss Remoting

----

*JBoss Remoting* is basically a connector type that is often exposed by *JBoss* products.
Using the remoting connector, you can access different kind of services. These can be default
services exposed by the *JBoss* application server (like e.g. *JMX*) or custom applications.
It can therefore be compared to *Jolokia* or even plain *RMI* and simply provides a transport
for the underlying application. That being said, *JBoss* remoting is more complex and
provides several features that are not available for other connector types.

From the network perspective, *JBoss Remoting* can sit behind regular *HTTP(S)* services. 
When starting a *Wildfly* server in it's default configuration, the management interface
can be found at port `9990` and can be accessed via regular *HTTP* using a web browser.
However, using the `Upgrade: jboss-remoting` header, the connection can be upgraded to
*JBoss Remoting* and switches to a persistent *TCP* connection that is used for data
exchange.

```http
GET / HTTP/1.1
Sec-JbossRemoting-Key: 2pidCCkW2KyzgTcuVQ9L6w==
Upgrade: jboss-remoting
Host: 127.0.0.1:9990
Connection: upgrade
```

```http
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: jboss-remoting
Content-Length: 0
Sec-JbossRemoting-Accept: YRw95YHhr/Wic0CJoLiOUpZIBU8=
Date: Thu, 28 Sep 2023 19:24:15 GMT
```

When you encounter a *JBoss* server with *HTTP(S)* endpoints, you can check whether they
support *JBoss Remoting* based *JMX* services by connecting with *beanshooter*. To tell
*beanshooter* that you want to use *JBoss Remoting*, you have to use the `--jndi` parameter
and specify your target like this:

```console
[user@host ~]$ beanshooter enum jboss.remoting.example 9993 --jndi service:jmx:remote+https
```

For this to work, you need to add a *JBoss Remoting* client library to the classpath. Since
classpath changes are not that straight forward when executing *.jar* files, *beanshooter*
adds the file `jboss-remoting.jar` to the class path automatically. Therefore, after
downloading a *JBoss Remoting* library, you just need to rename it to `jboss-remoting.jar`
and place it beside *beanshooter*. A compatible library at the time of writing can be obtained
like this:

```console
[user@host ~]$ wget -O 'jboss-remoting.jar' 'https://repo1.maven.org/maven2/org/wildfly/wildfly-client-all/29.0.1.Final/wildfly-client-all-29.0.1.Final.jar'
```

Depending on your target, you may need a different library version or even a complete
different library.


### Limitations

----

As in the case of the *Jolokia* connector, also the *JBoss Remoting* connector has some
limitations regarding beanshooter functionality. Certain actions, like for example preauth
deserialization attacks do not work using this connector. This is the case because the
authentication mechanism is not *RMI* based and does not rely on serialized Java objects
being send to the server.

*beanshooter* attempts to stop actions that do not work early. However, you might encounter
unusual error messages for cases that have not been caught by the error handling yet. Feel
free to report such issues in this project :)
