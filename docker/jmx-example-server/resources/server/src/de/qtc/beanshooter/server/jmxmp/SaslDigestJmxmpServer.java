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

import de.qtc.beanshooter.server.utils.AuthenticationCallbackHandler;

/**
 * JMXMP server that uses DIGEST-MD5 mechanism to authenticate incoming connections.
 * 
 * @author Tobias Neitzel (@qtc_de)
 */
public class SaslDigestJmxmpServer {

    private JMXConnectorServer server;

	/**
	 * Create the server object. The server uses fixed credentials:
	 * 	
	 * 		Username		Password
	 * 		controlRole		control
	 * 		monitorRole		monitor
	 * 
	 * @param port port number to create the server on
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 */
	public SaslDigestJmxmpServer(int port) throws IOException, NoSuchAlgorithmException
	{
		Map<String, Object> env = new HashMap<String, Object>();
		Map<String, String> creds = new HashMap<String, String>();

		creds.put("monitorRole", "monitor");
		creds.put("controlRole", "control");
		
		SSLContext ctx = SSLContext.getDefault();
        SSLSocketFactory ssf = ctx.getSocketFactory();
        
        env.put("jmx.remote.profiles", "TLS SASL/DIGEST-MD5");
        env.put("jmx.remote.sasl.callback.handler", new AuthenticationCallbackHandler(creds));
        env.put("jmx.remote.x.access.file", "/opt/jmxmp.access");
        env.put("jmx.remote.tls.socket.factory", ssf);
        env.put("com.sun.security.sasl.digest.realm", "iinsecure.dev");
        
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
