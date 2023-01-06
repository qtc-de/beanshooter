package de.qtc.beanshooter.server.jmxmp;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

import javax.management.MBeanServer;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

/**
 * Just a TLS protected JMXMP listener that does not require authentication.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SslJmxmpServer {

    private JMXConnectorServer server;

    /**
     * Create the server object. The server uses the globally configured TLS certificate.
     *
     * @param port port number to launch the server on
     * @throws IOException
     */
    public SslJmxmpServer(int port) throws IOException, NoSuchAlgorithmException
    {
        Map<String, Object> env = new HashMap<String, Object>();

        SSLContext ctx = SSLContext.getDefault();
        SSLSocketFactory ssf = ctx.getSocketFactory();

        env.put("jmx.remote.profiles", "TLS");
        env.put("jmx.remote.tls.socket.factory", ssf);

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
