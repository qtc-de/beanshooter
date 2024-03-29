package de.qtc.beanshooter.plugin.providers;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.cert.CertPathValidatorException;
import java.util.Map;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXServiceURL;

import org.jolokia.client.exception.J4pRemoteException;
import org.jolokia.client.exception.UncheckedJmxAdapterException;
import org.json.simple.parser.ParseException;

import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.MissingCredentialsException;
import de.qtc.beanshooter.exceptions.WrongCredentialsException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.IMBeanServerProvider;
import de.qtc.beanshooter.utils.ExtendedJolokiaJmxConnector;
import de.qtc.beanshooter.utils.Utils;

/**
 * The JolokiaProvider provides MBeanServerConnections using the official Jolokia JMX adapter. That being
 * said, the adapter was slightly extended to e.g. support proxy mode.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class JolokiaProvider implements IMBeanServerProvider {

    /**
     * The execution flow is automatically brought to this provider, when the user uses the --jolokia option.
     * The target host and port are when used to form the URI http(s)://<host>:<port>/jolokia. Using the
     * --jolokia-endpoint option, users can specify an alternative HTTP endpoint. Moreover, the arguments
     * --jolokia-proxy-target, --jolokia-proxy-user and --jolokia-proxy-pass allow to interact with Jolokia
     * running in proxy mode.
     */
    @SuppressWarnings("resource")
    @Override
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env) throws AuthenticationException, J4pRemoteException
    {
        MBeanServerConnection mBeanServerConnection = null;

        String endpoint = BeanshooterOption.CONN_JOLOKIA_ENDPOINT.getValue("/jolokia/");
        String connString = String.format("service:jmx:jolokia://%s:%d%s", host, port, endpoint);

        try
        {
            JMXServiceURL jmxUrl = new JMXServiceURL(connString);
            ExtendedJolokiaJmxConnector connector = new ExtendedJolokiaJmxConnector(jmxUrl, env, BeanshooterOption.CONN_JOLOKIA_PROXY.getValue());

            connector.connect();
            mBeanServerConnection = connector.getMBeanServerConnection();
        }

        catch (MalformedURLException e)
        {
            ExceptionHandler.internalError("DefaultMBeanServerProvider.getMBeanServerConnection", "Invalid URL.");
        }

        catch (UncheckedJmxAdapterException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof J4pRemoteException)
            {
                J4pRemoteException j4p = (J4pRemoteException)t;
                if (j4p.getStatus() == 401 || j4p.getStatus() == 403)

                    if (! j4p.getMessage().contains("not allowed by configuration"))

                        if (env.containsKey(JMXConnector.CREDENTIALS))
                            throw new WrongCredentialsException(e);

                        else
                            throw new MissingCredentialsException(e);

                throw j4p;
            }

            else if (t instanceof ParseException)
            {
                Logger.eprintlnMixedYellow("Caught", "ParseException", "while parsing the server response.");
                Logger.eprintlnMixedBlue("The specified target is", "probably not", "a Jolokia endpoint.");
                Utils.exit(e);
            }

            ExceptionHandler.unexpectedException(e, "while connecting", "to the jolokia endpoint", true);
        }

        catch (IOException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof java.net.ConnectException)
            {
                if (t.getMessage().contains("Connection refused"))
                {
                    Logger.eprintlnMixedBlue("The JMX remote object", "refused", "the connection.");
                }

                else if (t.getMessage().contains("Network is unreachable"))
                {
                    Logger.eprintlnMixedBlue("The JMX remote object is", "unreachable.");

                }

                else
                {
                    ExceptionHandler.unknownReason(e);
                }
            }

            else if (t instanceof java.rmi.ConnectIOException)
                   ExceptionHandler.connectIOException(e, "newclient");

            else if (t instanceof CertPathValidatorException)
            {
                Logger.eprintlnMixedBlue("The server probably uses TLS settings that are", "incompatible", "with your current security settings.");
                Logger.eprintlnMixedYellow("You may try to edit your", "java.security", "policy file to overcome the issue.");

                ExceptionHandler.showStackTrace(e);
            }

            else if (t instanceof java.io.EOFException || t instanceof java.net.SocketException)
            {
                Logger.eprintln("The JMX server closed the connection. This usually indicates a networking problem.");
                ExceptionHandler.showStackTrace(e);
            }

            else
            {
                Logger.eprintlnMixedYellow("Caught unexpected", "IOException", "while connecting to the specified JMX service.");
                ExceptionHandler.showStackTrace(e);
            }

            Utils.exit();
        }

        return mBeanServerConnection;
    }
}
