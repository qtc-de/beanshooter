### Some Technical Notes

----

Just some technical notes about *JMX* and *Java RMI* that I learned during building
this tool.


### Overwriting the Connection Target

----

During the registration process within the *RMI registry*, some *JMX* endpoints register
their objects for *localhost* access, whereas the actual *RMI ports* are still accessible
from the out side.

This is a common misconfiguration that occurs than setting ``java.rmi.server.hostname=localhost``,
but not restricting the actual access to the *RMI ports*. The property
``java.rmi.server.hostname`` only controlös the host name that is set in the *RMI stubs*
that are exposed by the application server. When using the corresponding stub, all connection
attempts are indeed targeting localhost, but the *RMI port* is accessible on all interfaces
none the less.

From an attackers perspective, setting ``localhost`` or ``127.0.0.1`` as hostname inside the
*RMI stub* is still annoying, as standard tools can no longer be used to connect to the
remote *RMI port*. Tools like [mjet](https://github.com/mogwailabs/mjet) solve this issue
by creating a localhost proxy listener, that forwards all traffic to the remote endpoint.
*Beanshooter* chooses a different approach by modifying the corresponding socket factories.


#### Non-SSL Connections

For *non-SSL* connections, this is really simple. From the documentation of the ``RMISocketFactory``
interface once can obtain the following information about the ``setSocketFactory`` method:

> setSocketFactory(RMISocketFactory fac)
> Set the global socket factory from which RMI gets sockets (if the remote object is not associated with a specific client and/or server socket factory).

When *JMX* is used without *SSL*, where is no need to specify a custom ``RMIClientSocketFactory`` during
the call to ``exportObject``. Therefore, no specific factory is associated with the remote object
and ``RMISocketFactory.setSocketFactory(fac)`` can be used to override the default. In the source of
*beanshooter*, this looks like this:

```java
RMISocketFactory fac = RMISocketFactory.getDefaultSocketFactory();
RMISocketFactory my = new LoopbackSocketFactory(host, fac, followRedirect);
RMISocketFactory.setSocketFactory(my);
```

The custom ``LoopbackSocketFactory`` redirects all connections to different hosts back to the actual target
and uses the ``DefaultSocketFactory`` for the actual connections.


#### SSL Connections

For connections using *SSL*, the situation is a little bit more tricky. In this case, the *RMI server* usually
sets the ``SslRMIClientSocketFactory`` as custom socket factory during the ``exportObject`` call. Therefore,
using ``RMISocketFactory.setSocketFactory`` has no effect on *SSL connections*.

However, looking at the source of ``SslRMIClientSocketFactory`` reveals, that it uses ``SSLSocketFactory.getDefault()``
internally to obtain an ``SocketFactory``.

```java
public class SslRMIClientSocketFactory implements RMIClientSocketFactory, Serializable {

    [...]
    public Socket createSocket(String host, int port) throws IOException {

        final SocketFactory sslSocketFactory = getDefaultClientSocketFactory();
        final SSLSocket sslSocket = (SSLSocket)sslSocketFactory.createSocket(host, port);

    [...]
    private static SocketFactory defaultSocketFactory = null;

    private static synchronized SocketFactory getDefaultClientSocketFactory() {
        if (defaultSocketFactory == null)
            defaultSocketFactory = SSLSocketFactory.getDefault();
        return defaultSocketFactory;
    }
}
```

The ``SSLSocketFactory.getDefault()``, on the other hand, looks for the property ``ssl.SocketFactory.provider`` to determine
the class that is used for creating the ``SocketFactory``.

```java
public static synchronized SocketFactory getDefault() {
      if (theFactory != null) {
          return theFactory;
      }

      if (propertyChecked == false) {
          propertyChecked = true;
          String clsName = getSecurityProperty("ssl.SocketFactory.provider");
      [...]
```

Therefore, by setting this property to a custom ``SocketFactory`` class, it is also possible to overwrite the factory
used for *SSL* protected *RMI connections*. In *beanshooter*, this looks like this:

```java
SSLContext ctx = SSLContext.getInstance("TLS");
ctx.init(null, new TrustManager[] { new DummyTrustManager() }, null);
SSLContext.setDefault(ctx);

LoopbackSslSocketFactory.host = host;
LoopbackSslSocketFactory.fac = ctx.getSocketFactory();
LoopbackSslSocketFactory.followRedirect = followRedirect;
java.security.Security.setProperty("ssl.SocketFactory.provider", "de.qtc.beanshooter.LoopbackSslSocketFactory");
```

As the ``ssl.SocketFactory.provider`` needs to have a *nullary constructor*, the required paramaters have to been set
as class variables. Also the ``LoopbackSslSocketFactory`` just redirects all connections back to the targeted host
and uses the ``ctx.getSocketFactory()`` for the actual connection attempts.
