## Docker Container

If you want to test *jmx-exploiter*, you can do this using the docker container provided in this repository.
The *docker-compose.yml* file in this folder builds a docker container based on the *tomcat9-alpine* image.
The server has JMX enabled and also provides a JMXMP listener. Shout-outs go to [nickman](https://github.com/nickman)
for providing a [JMXMPAgent implementation](https://github.com/nickman/JMXMPAgent).


### Configuration Details

-----

* -Dcom.sun.management.jmxremote 
* -Dcom.sun.management.jmxremote.local.only=false 
* -Dcom.sun.management.jmxremote.authenticate=false 
* -Dcom.sun.management.jmxremote.port=9010 
* -Dcom.sun.management.jmxremote.rmi.port=9010 
* -Djava.rmi.server.hostname=172.30.0.2 
* -Dcom.sun.management.jmxremote.ssl=false

Please notice that the container starts on a fixed ip address. When starting the container without a fixed
address and without the **hostname** option, the rmi registry redirects the JMX query always to 127.0.0.1.
Not sure how to fix this in a better way than setting a fixed ip address, but this should work as a workaround.
The JMXMP listener will start on port 8888.

Notice that the **docker-compose.yml** file does not map any container ports to your docker host system. Therfore, you
have to target the ip address of the docker container directly to connect to the exposed services.


### Startup and Shutdown

-----

Make sure you have installed docker compose:

```bash
pip install docker-compose
```

For starting and stopping the container you can simply use the following commands:

```bash
docker-compose up # Startup
docker-compose stop # Shutdown
```
