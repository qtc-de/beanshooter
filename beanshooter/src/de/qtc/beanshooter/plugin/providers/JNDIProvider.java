package de.qtc.beanshooter.plugin.providers;

import java.io.IOException;
import java.net.MalformedURLException;
import java.rmi.server.RMISocketFactory;
import java.util.Map;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import javax.rmi.ssl.SslRMIClientSocketFactory;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.IMBeanServerProvider;
import de.qtc.beanshooter.plugin.PluginSystem;
import de.qtc.beanshooter.utils.Utils;

/**
 * The JNDIProvider provides MBeanServerConnections using a JNDI lookup. It has been tested for
 * RMI based connections only so far.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class JNDIProvider implements IMBeanServerProvider {

    /**
     * Obtain the user specified JNDI string (--jndi <JNDI-STING>) from the command line and use it as a
     * JMXServiceURL. The JNDI string may contain two %s placeholders that are replaced with the specified
     * host and port values.
     */
    @Override
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env)
    {
        MBeanServerConnection mBeanServerConnection = null;
        String connString = ArgumentHandler.require(BeanshooterOption.CONN_JNDI);

        java.security.Security.setProperty("ssl.SocketFactory.provider", PluginSystem.getDefaultSSLSocketFactoryClass(host, port));

        if (BeanshooterOption.CONN_SSL.getBool())
            env.put("com.sun.jndi.rmi.factory.socket", new SslRMIClientSocketFactory());

        try
        {
            RMISocketFactory.setSocketFactory(PluginSystem.getDefaultRMISocketFactory(host, port));
        }

        catch (IOException e)
        {
            Logger.eprintlnMixedBlue("Unable to set custom", "RMISocketFactory.", "Host redirection will probably not work.");
            ExceptionHandler.showStackTrace(e);
            Logger.eprintln("");
        }

        try
        {
            JMXServiceURL jmxUrl = new JMXServiceURL(String.format(connString, host, port));
            JMXConnector jmxConnector = JMXConnectorFactory.connect(jmxUrl, env);

            mBeanServerConnection = jmxConnector.getMBeanServerConnection();
        }

        catch (MalformedURLException e)
        {
            ExceptionHandler.internalError("DefaultMBeanServerProvider.getMBeanServerConnection", "Invalid URL.");
            Utils.exit(e);
        }

        catch (IOException e)
        {
            Logger.eprintlnMixedYellow("Caught unexpected", "IOException", "while connecting to the specified JMX service.");
            Utils.exit(e);
        }

        return mBeanServerConnection;
    }
}
