package de.qtc.beanshooter.plugin;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.server.RMISocketFactory;
import java.util.Map;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import javax.rmi.ssl.SslRMIClientSocketFactory;

import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.utils.Utils;

/**
 * The JNDIProvider provides MBeanServerConnections using a JNDI lookup.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class JNDIProvider implements IMBeanServerProvider {

    private static final String connString = "service:jmx:rmi:///jndi/rmi://%s:%s/%s";

    @Override
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env)
    {
        MBeanServerConnection mBeanServerConnection = null;
        String boundName = Option.require(Option.TARGET_BOUND_NAME);

        if( Option.CONN_SSL.getBool() )
            env.put("com.sun.jndi.rmi.factory.socket", new SslRMIClientSocketFactory());

        java.security.Security.setProperty("ssl.SocketFactory.provider", PluginSystem.getDefaultSSLSocketFactory(host, port));

        try {
            RMISocketFactory.setSocketFactory(PluginSystem.getDefaultSocketFactory(host, port));

        } catch (IOException e) {
            Logger.eprintlnMixedBlue("Unable to set custom", "RMISocketFactory.", "Host redirection will probably not work.");
            ExceptionHandler.showStackTrace(e);
            Logger.eprintln("");
        }

        try {
            JMXServiceURL jmxUrl = new JMXServiceURL(String.format(connString, host, port, boundName));
            JMXConnector jmxConnector = JMXConnectorFactory.connect(jmxUrl, env);

            mBeanServerConnection = jmxConnector.getMBeanServerConnection();

        } catch (MalformedURLException e) {
            ExceptionHandler.internalError("DefaultMBeanServerProvider.getMBeanServerConnection", "Invalid URL.");

        } catch (IOException e) {
            Logger.eprintlnMixedYellow("Caught unexpected", "IOException", "while connecting to the specified JMX service.");
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }

        return mBeanServerConnection;
    }

}