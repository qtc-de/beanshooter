package de.qtc.beanshooter.server.rmi;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.util.HashMap;
import java.util.Map;

import javax.management.MBeanServer;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.management.remote.rmi.RMIConnectorServer;
import javax.rmi.ssl.SslRMIClientSocketFactory;
import javax.rmi.ssl.SslRMIServerSocketFactory;

import de.qtc.beanshooter.server.utils.SimplePasswordAuthenticator;

/**
 * TLS protected RMI based JMX server that uses a password based authenticator. This server does intentionally
 * not use environment variables to launch the default JMX service in an secure configured way. Instead we configure
 * it our own and make it vulnerable e.g. to preauth deserialization attacks.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SslJmxConnector {

    private JMXConnectorServer server;

    /**
     * Creates an TLS protected RMI based JMX server that is additionally protected by simple
     * password based authentication. The server uses the custom bound name "secure-jmxrmi"
     *
     * @param port port of an RMI Registry server on the local system
     * @throws IOException
     */
    public SslJmxConnector(int port) throws IOException
    {
         Map<String, Object> env = new HashMap<String, Object>();

         SimplePasswordAuthenticator authenticator = new SimplePasswordAuthenticator();
         authenticator.addCredential("admin", "admin");

         env.put(RMIConnectorServer.RMI_SERVER_SOCKET_FACTORY_ATTRIBUTE, new SslRMIServerSocketFactory());
         env.put(RMIConnectorServer.RMI_CLIENT_SOCKET_FACTORY_ATTRIBUTE, new SslRMIClientSocketFactory());
         env.put(JMXConnectorServer.AUTHENTICATOR, authenticator);

         MBeanServer mbeanServer = ManagementFactory.getPlatformMBeanServer();
         JMXServiceURL url = new JMXServiceURL("service:jmx:rmi:///jndi/rmi://127.0.0.1:" + port + "/secure-jmxrmi");

         server = JMXConnectorServerFactory.newJMXConnectorServer(url, env, mbeanServer);
    }

    /**
     * Starts the JMX service. This binds the "secure-jmxrmi" bound name to the RMI registry and exports the
     * corresponding remote object.
     *
     * @throws IOException
     */
    public void start() throws IOException
    {
        server.start();
    }
}
