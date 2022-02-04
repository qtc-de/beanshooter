package de.qtc.beanshooter.operation;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.management.MBeanServerConnection;
import javax.management.ObjectInstance;
import javax.management.remote.JMXConnector;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.cli.SASLMechanism;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.InvalidLoginClassException;
import de.qtc.beanshooter.exceptions.SaslMissingException;
import de.qtc.beanshooter.exceptions.SaslProfileException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.plugin.PluginSystem;

/**
 * Helper class to divide the different checks during the enum action into separate functions.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class EnumHelper
{
    private final String host;
    private final int port;

    private MBeanServerClient client;

    public EnumHelper(String host, int port)
    {
        this.host = host;
        this.port = port;
    }

    /**
     * Attempts a login without credentials on the remote MBeanServer. Success or failure is reported within
     * the status messages.
     *
     * @param printIntro
     * @return true if access is possible
     */
    public boolean enumAccess()
    {
        Map<String, Object> env = ArgumentHandler.getEnv(null, null);

        Logger.printlnBlue("Checking for unauthorized access:");
        Logger.lineBreak();
        Logger.increaseIndent();

        try {
            MBeanServerConnection conn = PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);

            Logger.printlnMixedYellow("- Remote MBean server", "does not", "require authentication.");
            Logger.statusVulnerable();

            client = new MBeanServerClient(conn);
            return true;
        }

        catch (AuthenticationException e) {
            String message = e.getMessage();

            if (isCredentialException(message)) {
                Logger.printlnMixedYellow("- Remote MBean server", "requires authentication.");
                Logger.statusOk();
            }

            else {
                Logger.printlnMixedYellow("- Caught unexpected", "AuthenticationException", "during login attempt.");
                Logger.statusUndecided("Vulnerability");
            }

            ExceptionHandler.showStackTrace(e);
        }

        catch (Exception e) {
            Logger.printlnMixedYellow("- Caught unexpected", e.getClass().getName(), "during login attempt.");
            Logger.statusUndecided("Vulnerability");
            ExceptionHandler.showStackTrace(e);
        }

        finally {
            Logger.decreaseIndent();
        }

        return false;
    }

    /**
     * Attempts to enumerate the SASL mechanism. This function first attempts to establish an MBeanServerConnection
     * without using SASL and TLS. If this does not work, it attempts to connect with the SASL TLS profile. These are
     * the possibilities where password protection is missing.
     *
     * If none of the above succeeds, the function attempts to establish a connection using each SASL mechanism and
     * checks the exception that is thrown by the server. The first mechanism that does not throw an exception based
     * on a SASL profile mismatch is interpreted as the configured server mechanism.
     *
     * @return true if access is possible
     */
    public boolean enumSASL()
    {
        Map<String, Object> env = ArgumentHandler.getEnv(null, null);

        Logger.printlnBlue("Checking servers SASL configuration:");
        Logger.lineBreak();
        Logger.increaseIndent();

        boolean sslOrig = BeanshooterOption.CONN_SSL.getBool();
        BeanshooterOption.CONN_SASL.setValue(null);

        for (boolean sslValue : new boolean[] { false, true })
        {
            BeanshooterOption.CONN_SSL.setValue(sslValue);

            try {
                MBeanServerConnection conn = PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);

                if (sslValue) {
                    Logger.printlnMixedYellow("- Remote JMXMP server uses", "TLS SASL", "profile.");
                    Logger.printMixedBlue("  Login is possible", "without", "credentials when using the ");
                    Logger.printlnPlainMixedYellowFirst("--ssl", "option.");
                }

                else {
                    Logger.printlnMixedYellow("- Remote JMXMP server", "does not", "use SASL.");
                    Logger.printlnMixedBlue("  Login is possible", "without", "specifying credentials.");
                }

                Logger.statusVulnerable();
                client = new MBeanServerClient(conn);
                return true;
            }

            catch (SaslMissingException e)
            {
                ExceptionHandler.showStackTrace(e);
            }

            catch (SaslProfileException e)
            {
                ExceptionHandler.showStackTrace(e);
            }

            catch (Exception e)
            {
                Logger.printlnMixedYellow("- Caught unexpected", e.getClass().getName(), "during login attempt.");
                Logger.statusUndecided("Vulnerability");
                ExceptionHandler.showStackTrace(e);
                return false;
            }

            finally
            {
                BeanshooterOption.CONN_SSL.setValue(sslOrig);
                Logger.decreaseIndent();
            }
        }

        BeanshooterOption.CONN_USER.setValue("non existent dummy user");
        BeanshooterOption.CONN_PASS.setValue("non existing dummy password");
        env = ArgumentHandler.getEnv();

        SASLMechanism mechanism = SASLMechanism.detectMechanis(host, port, env);
        Logger.increaseIndent();

        if( mechanism != null)
        {
            Logger.printlnMixedYellow("- Remote JMXMP server uses", mechanism.getProfile(), "SASL profile.");
            Logger.statusOk();
        }

        else
        {
            Logger.printlnMixedYellow("- Remote JMXMP server", "probably uses SASL", " but the profile coldn't be enumerated.");
            Logger.statusUndecided("Vulnerability");
        }

        Logger.decreaseIndent();
        return false;
    }

    /**
     * Checks whether preauth deserialization attacks are possible on the remote MBeanServer.
     * This check is currently only implemented for RMI based endpoints. Concerning JMXMP, we
     * could just start by sending an arbitrary object and see how the server reacts. However,
     * during the first tests the server just cuts the connection without returning an exception.
     * To enumerate whether the connection was cut because of a ClassCastException or an rejected
     * deserialization, we need a more dedicated approach. That being said, JMXMP is really uncommon
     * these days and the probability of encountering an deserialization filtered JMXMP endpoint
     * is probably near 0%.
     */
    public void enumSerial()
    {
        Logger.printlnBlue("Checking pre-auth deserialization behavior:");
        Logger.lineBreak();
        Logger.increaseIndent();

        if (BeanshooterOption.CONN_JMXMP.getBool())
        {
            Logger.printlnMixedYellow("JMXMP serial check is","work in progress", "but endpoints are usually vulnerable.");
            Logger.statusUndecided("Configuration");
            return;
        }

        Map<String,Object> env = new HashMap<String,Object>();
        env.put(JMXConnector.CREDENTIALS, new HashMap<String,String>());

        try
        {
            PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);

            Logger.printlnMixedYellow("- Remote MBeanServer",  "accepted", "the payload class.");
            Logger.statusNonDefault();
        }

        catch (InvalidLoginClassException e)
        {
            Logger.printlnMixedYellow("- Remote MBeanServer", "rejected", "the payload class.");
            Logger.statusOk();
        }

        catch (AuthenticationException e)
        {
            Logger.printlnMixedYellow("- Remote MBeanServer",  "accepted", "the payload class.");
            Logger.statusNonDefault();
        }

        finally
        {
            Logger.decreaseIndent();
        }
    }

    /**
     * Enumerate the available MBeans on the target system and dispaly their class names together
     * with their ObjectNames.
     */
    public void enumMBeans()
    {
        if (client == null)
            return;

        Logger.printlnBlue("Listing available MBeans:");
        Logger.lineBreak();
        Logger.increaseIndent();

        Set<ObjectInstance> mbeans = client.getMBeans();
        for(ObjectInstance instance : mbeans)
        {
            Logger.printMixedYellow("-", instance.getClassName(), "");
            Logger.printlnPlainBlue("(" + instance.getObjectName().toString() + ")");
        }
    }

    /**
     * Checks whether an Exception message was related to missing credentials.
     *
     * @param message Exception message
     * @return true if the message complains about missing credentials
     */
    private boolean isCredentialException(String message)
    {
        String[] authMessages = new String[] { "Credentials required", "Authentication required" };

        for (String item : authMessages)

            if (message.contains(item))
                return true;

        return false;
    }
}
