### Jolokia Example Server

----

The *jolokia-example-server* is a docker container that runs an *Apache tomcat service* that exposes
*JMX* services on two different endpoints. The first endpoint is `1090/TCP` that supports regular
*RMI* based *JMX* connections. The second one is `8080/TCP` that supports *JMX* connections via
[Jolokia](https://github.com/rhuss/jolokia).

*Jolokia* is configured to allow [proxy mode](https://jolokia.org/reference/html/proxy.html). To test
proxy mode, you can either proxy to the *RMI* based *JMX* endpoint on the same server or you can launch
an additional container e.g. by using ad [docker-compose.yml](./docker-compose.yml) like this:

```yml
version: '3.7'

services:
    tomcat:
      image: ghcr.io/qtc-de/beanshooter/jolokia-example-server:1.0

    backend-jmx:
      image: ghcr.io/qtc-de/beanshooter/jmx-example-server:2.0
```
