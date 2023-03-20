package de.qtc.beanshooter.plugin.providers;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Map;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.cli.SASLMechanism;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.SaslMissingException;
import de.qtc.beanshooter.exceptions.SaslProfileException;
import de.qtc.beanshooter.exceptions.SaslSuperflousException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOperation;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.IMBeanServerProvider;
import de.qtc.beanshooter.plugin.PluginSystem;
import de.qtc.beanshooter.utils.Utils;

/**
 * The JMXMP provider provides MBeanServerConnections by using the JMXMP protocol.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class JMXMPProvider implements IMBeanServerProvider {

    private static final String connString = "service:jmx:jmxmp://%s:%s";

    /**
     * Obtain the required values from the command line and establish an JMXMP based MBeanServerConnection
     * with them.
     */
    @Override
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env) throws AuthenticationException
    {
        MBeanServerConnection mBeanServerConnection = null;

        java.security.Security.setProperty("ssl.SocketFactory.provider", PluginSystem.getDefaultSSLSocketFactoryClass(host, port));

        if (BeanshooterOption.CONN_SSL.getBool())
        {
            env.put("jmx.remote.tls.socket.factory", PluginSystem.getSSLSocketFactory(host, port));
            env.put("jmx.remote.profiles", "TLS");
        }

        SASLMechanism saslMechanism = ArgumentHandler.getSASLMechanism();
        if (saslMechanism != null)
        {
            if (!env.containsKey(JMXConnector.CREDENTIALS) && ArgumentHandler.getInstance().getAction() != BeanshooterOperation.BRUTE)
                ArgumentHandler.requireAllOf(BeanshooterOption.CONN_USER, BeanshooterOption.CONN_PASS);

            String[] credentials = (String[]) env.get(JMXConnector.CREDENTIALS);

            saslMechanism.init(env, credentials[0], credentials[1]);
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
        }

        catch (IOException e)
        {
            Throwable t = ExceptionHandler.getCause(e);
            String message = t.getMessage();

            if( t instanceof IOException && message.contains("negotiated profiles do not match") )
                throw new SaslProfileException(e, true);

            if( t instanceof IOException && message.contains("do not match the client required profiles") )
                throw new SaslProfileException(e, true);

            if( t instanceof IOException && message.contains("not require any profile but the server mandates on") )
                throw new SaslMissingException(e, true);

            if( t instanceof IOException && message.contains("The server does not support any profile") )
                throw new SaslSuperflousException(e, true);

            Logger.eprintlnMixedYellow("Caught unexpected", "IOException", "while connecting to the specified JMX service.");
            Utils.exit(e);
        }

        catch( java.lang.SecurityException e )
        {
            ExceptionHandler.handleSecurityException(e);
        }

        return mBeanServerConnection;
    }

}
