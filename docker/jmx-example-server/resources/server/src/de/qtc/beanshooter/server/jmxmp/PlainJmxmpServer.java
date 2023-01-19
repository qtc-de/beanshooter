package de.qtc.beanshooter.server.jmxmp;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.HashMap;
import java.util.Map;

import javax.management.MBeanServer;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;

/**
 * Just a plain JMXMP listener that does not require authentication.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class PlainJmxmpServer {

    private JMXConnectorServer server;

    /**
     * Create the server object.
     *
     * @param port port number to launch the server on
     * @throws IOException
     */
    public PlainJmxmpServer(int port) throws IOException
    {
        Map<String, Object> env = new HashMap<String, Object>();

        MBeanServer mbeanServer = ManagementFactory.getPlatformMBeanServer();
        JMXServiceURL url = new JMXServiceURL("jmxmp", "0.0.0.0", port);

        server = JMXConnectorServerFactory.newJMXConnectorServer(url, env, mbeanServer);
    }

    /**
     * Start the server.
     *
     * @throws IOException
     */
    public void start() throws IOException
    {
        server.start();
    }
}
