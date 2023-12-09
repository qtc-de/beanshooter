package eu.tneitzel.beanshooter.server.jmxmp;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;

import javax.management.MBeanServer;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import com.sun.jdmk.security.sasl.Provider;

import eu.tneitzel.beanshooter.server.utils.AuthenticationCallbackHandler;

/**
 * JMXMP server that uses SASL Plain mechanism to authenticate incoming connections.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SaslPlainJmxmpServer {

    private JMXConnectorServer server;

    /**
     * Create the server object. The server uses fixed credentials:
     *
     *         Username        Password
     *         controlRole        control
     *         monitorRole        monitor
     *
     * @param port port number to create the server on
     * @throws IOException
     * @throws NoSuchAlgorithmException
     */
    public SaslPlainJmxmpServer(int port) throws IOException, NoSuchAlgorithmException
    {
        Map<String, Object> env = new HashMap<String, Object>();
        Map<String, String> creds = new HashMap<String, String>();

        creds.put("monitorRole", "monitor");
        creds.put("controlRole", "control");

        SSLContext ctx = SSLContext.getDefault();
        SSLSocketFactory ssf = ctx.getSocketFactory();

        Provider saslPlainProvider = new Provider();
        Security.addProvider(saslPlainProvider);

        env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
        env.put("jmx.remote.sasl.callback.handler", new AuthenticationCallbackHandler(creds));
        env.put("jmx.remote.x.access.file", "/opt/jmxmp.access");
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
