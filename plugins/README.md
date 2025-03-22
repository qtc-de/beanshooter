### Plugins

----

*beanshooter* can be extended with plugins. Plugins are *jar* files that
can provide implementations for certain interfaces used by *beanshooter*.
If a plugin was specified using the `--plugin` option, *beanshooter* uses
the plugin implementation for the corresponding interface instead of using it's own
one.


### Available plugins

----

It is generally recommended to maintain plugins within a separate repository
within your own namespace. This makes plugin development easier, as modifications
can be applied by yourself insead of relying on pull requests.

That being said, plugins can also be added to the *beanshooter* repository to make them
visible to everyone. I'm also happy to update the following plugin list with a reference
to your plugin repository :)

At the time of writing, the following *beanshooter* plugins are available:

* None :P


### Plugin Development

----

When developing a new plugin, it is recommended to use the [plugin template](/plugins/template)
provided in this repository. It provides a ready to use *maven* template to get
started with plugin development. [Template.java](/plugins/template/src/main/java/eu/tneitzel/beanshooter/plugin/Template.java)
contains a class with dummy implementations for all supported interfaces.

Plugin *jar* files need to contain a specific entry within their manifest to be usable
with *beanshooter*:

```
BeanshooterPluginClass: eu.tneitzel.beanshooter.plugin.Template
```

This entry is set automatically when using the provided maven template. Otherwise,
it needs to be added manually. For access to *beanshooter* classes and methods,
you can import it via maven:

```xml
<dependencies>
    <dependency>
        <groupId>eu.tneitzel</groupId>
        <artifactId>remote-method-guesser</artifactId>
        <version>5.1.0</version>
        <scope>provided</scope>
    </dependency>
</dependencies>
```


### Supported Interfaces

----

This section contains a list of currently supported interfaces. More details can be
found within the [plugin template](/plugins/template).

#### IArgumentProvider

`IArgumentProvider` is used when performing MBean calls using the `invoke` action. It can be
used to provide more Java objects used as call arguments that cannot be created using *beanshooters*
command line eval machanism.

#### IAuthenticationProvider

JMX endpoints that require authentication are often using a HashMap that contains the credential
information. The default JMX implementation if OpenJDK for example, expects the credentials to
be contained within the key `JMXConnector.CREDENTIALS`. This is also the default that is used by
*beanshooter*. If you need a different HashMap layout, you can implement this interface to provide
your custom HashMap.

#### IMBeanServerProvider

MBean calls get usually invoked using an `MBeanServerConnection` object. The underlying communication
channel can be different. *beanshooter* implements the *RMI*, *JMXMP* and *HTTP* (Jolokia) channels by
default. In cases you need a different channel, you can implement this interface to provide your own
mechanism for obtaining an `MBeanServerConnection` object.

#### IPayloadProvider

`IPayloadProvider` is used when performing deserialization attacks. By using this interface, you can
provide custom gadget objects that will be send to the MBean server.

#### IResponseHandler

When using the `invoke` action, the MBean server may return arbitrary objects. By default, *beanshooter*
attempts to create a string representation of all return values, but this may fail for complex object
types. Using `IResponseHandler`, you can tell *beannshooter* how it should process response objects.

#### ISocketFactoryProvider

When using the RMI channel, custom socket factory classes can be used for the underlying network
communication. This rarely happens, but you see it from time to time. In case *beanshooters* default
socket factories do not work, you can use `ISocketFactoryProvider` to provide a custom implementation.
