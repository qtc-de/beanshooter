package eu.tneitzel.beanshooter.server.rmi;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.HashMap;
import java.util.Map;

import javax.management.MBeanServer;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;

/**
 * Plain RMI based JMX server.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class PlainJmxConnector {

    private JMXConnectorServer server;

    /**
     * Creates the server object.
     *
     * @param port port of an RMI Registry server on the local system
     * @throws IOException
     */
    public PlainJmxConnector(int port) throws IOException
    {
         Map<String, Object> env = new HashMap<String, Object>();

         MBeanServer mbeanServer = ManagementFactory.getPlatformMBeanServer();
         JMXServiceURL url = new JMXServiceURL("service:jmx:rmi:///jndi/rmi://127.0.0.1:" + port + "/jmxrmi");

         server = JMXConnectorServerFactory.newJMXConnectorServer(url, env, mbeanServer);
    }

    /**
     * Starts the JMX service. This binds the jmxrmi bound name to the RMI registry and exports the corresponding
     * remote object.
     *
     * @throws IOException
     */
    public void start() throws IOException
    {
        server.start();
    }
}
