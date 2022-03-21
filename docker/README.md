### Docker Containers

---

This directory contains the sources to build the *beanshooter* example servers. These are docker
containers that expose intentionally vulnerable *JMX* services. These can be used to practice usage
of *beanshooter* and to understand the attack surface on *JMX* endpoints.

The following containers are currently available:

* [jmx-example-server](./jmx-example-server) - This container exposes several ports that can be used to
  access the *JMX* agent. Some of them can be accessed without authentication, others require valid
  credentials. There are *RMI* based *JMX* endpoints and *JMX* endpoints that need to be contacted via
  *JMXMP*. The different *JMXMP* endpoints all use different *SASL* mechanisms.
* [tomcat](./tomcat) - Just a plain *Apache tomcat* server with *JMX* enabled. This can be used to verify
  that *beanshooters tomcat* related actions work like expected.
