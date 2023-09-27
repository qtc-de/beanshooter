package de.qtc.beanshooter.plugin.providers;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.cert.CertPathValidatorException;
import java.util.Map;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import javax.security.auth.callback.UnsupportedCallbackException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.GlassFishException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOperation;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.IMBeanServerProvider;
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
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env) throws AuthenticationException
    {
        MBeanServerConnection mBeanServerConnection = null;
        String connString = ArgumentHandler.require(BeanshooterOption.CONN_JNDI);

        try
        {
            JMXServiceURL jmxUrl = new JMXServiceURL(String.format(connString, host, port));
            JMXConnector jmxConnector = JMXConnectorFactory.connect(jmxUrl, env);

            mBeanServerConnection = jmxConnector.getMBeanServerConnection();
        }

        catch (MalformedURLException e)
        {
        	String message = e.getMessage();

        	if (message.contains("Unsupported protocol"))
        	{
        		String protocol = message.split(": ")[1];

	            Logger.eprintlnMixedYellow("The specified protocol", protocol, "is not supported by your Java installation.");
	            Logger.eprintlnMixedBlue("You probably need to", "extend the classpath", "to make it work.");
	            ExceptionHandler.showStackTrace(e);
	            Utils.exit(e);
        	}

        	else
        	{
	            Logger.eprintlnMixedYellow("Caught unexpected", "MalformedURLException", "during JNDI lookup.");
	            Logger.eprintlnMixedBlue("The specified", "JNDI URL", "seems to be invalid.");
	            ExceptionHandler.showStackTrace(e);
	            Utils.exit(e);
        	}
        }

        catch (IOException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof java.rmi.ConnectIOException)
                ExceptionHandler.connectIOException(e, "newclient");

            else if (t instanceof java.io.NotSerializableException && t.getMessage().contains("PrincipalCallback"))
                throw new GlassFishException(e);

            else if (t instanceof UnsupportedCallbackException)
                ExceptionHandler.unsupportedCallback((Exception)t);

            Logger.resetIndent();
            Logger.eprintlnMixedYellow("Caught", t.getClass().getName(), "while invoking the newClient method.");

            if (t instanceof java.net.ConnectException)
            {
                if (t.getMessage().contains("Connection refused"))
                {
                    Logger.eprintlnMixedBlue("The server", "refused", "the connection.");
                }

                else if (t.getMessage().contains("Network is unreachable"))
                {
                    Logger.eprintlnMixedBlue("The server seems", "unreachable.");

                }

                else
                {
                    ExceptionHandler.unknownReason(e);
                }

                if (BeanshooterOption.TARGET_OBJID_CONNECTION.isNull())
                {
                    Logger.eprintlnMixedYellow("The reference returned by the", "JDNI lookup", "is probably pointing to an invalid server.");
                }
            }

            else if (t instanceof java.io.EOFException || t instanceof java.net.SocketException)
            {
                Logger.eprintln("The server closed the connection. This usually indicates a networking problem.");
            }

            else if (ArgumentHandler.getInstance().getAction() == BeanshooterOperation.SERIAL && BeanshooterOption.SERIAL_PREAUTH.getBool())
            {
                Logger.eprintlnMixedBlue("This exception could be caused by the selected gadget and the deserialization attack may", "worked anyway.");

                if (!BeanshooterOption.GLOBAL_STACK_TRACE.getBool())
                {
                    Logger.eprintlnMixedYellow("If it did not work you may want to rerun with the", "--stack-trace", "option to further investigate.");
                }
            }

            else if (t instanceof CertPathValidatorException)
            {
                Logger.eprintlnMixedBlue("The server probably uses TLS settings that are", "incompatible", "with your current security settings.");
                Logger.eprintlnMixedYellow("You may try to edit your", "java.security", "policy file to overcome the issue.");
                Utils.exit(e);
            }

            else if (t instanceof javax.security.sasl.SaslException)
            {
	            Logger.eprintlnMixedBlue("You probably need to", "specify credentials", "to connect to this server.");
	            Utils.exit(e);
            }

            else
            {
                ExceptionHandler.unknownReason(e);
            }

            Utils.exit(e);
        }

        return mBeanServerConnection;
    }
}
