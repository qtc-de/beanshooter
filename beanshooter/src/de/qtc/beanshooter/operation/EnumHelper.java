package de.qtc.beanshooter.operation;

import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import javax.management.MBeanServerConnection;
import javax.management.ObjectInstance;
import javax.management.remote.JMXConnector;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.cli.SASLMechanism;
import de.qtc.beanshooter.exceptions.ApacheKarafException;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.InvalidLoginClassException;
import de.qtc.beanshooter.exceptions.MismatchedURIException;
import de.qtc.beanshooter.exceptions.MissingCredentialsException;
import de.qtc.beanshooter.exceptions.SaslMissingException;
import de.qtc.beanshooter.exceptions.SaslProfileException;
import de.qtc.beanshooter.exceptions.WrongCredentialsException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.plugin.PluginSystem;
import de.qtc.beanshooter.utils.Utils;

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
     * If a password and a username was specified for the enum action, we perform a regular login.
     *
     * @return true if login was successful
     */
    public boolean login()
    {
        Map<String, Object> env = ArgumentHandler.getEnv();

        Logger.printlnBlue("Checking specified credentials:");
        Logger.lineBreak();
        Logger.increaseIndent();

        try
        {
            MBeanServerConnection conn = PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);

            Logger.printlnMixedYellowFirst("- Login successful!", "The specified credentials are correct.");
            Logger.printMixedBlue("  Username:", BeanshooterOption.CONN_USER.getValue(), " - ");
            Logger.printlnPlainMixedBlue("Password:", BeanshooterOption.CONN_PASS.getValue());

            client = new MBeanServerClient(conn);
            return true;
        }

        catch (AuthenticationException e)
        {
            Logger.printlnMixedYellow("- Caught", "AuthenticationException", "during login attempt.");
            Logger.statusUndecided("Configuration");
            ExceptionHandler.showStackTrace(e);
        }

        catch (Exception e) {
            Logger.printlnMixedYellow("- Caught unexpected", e.getClass().getName(), "during login attempt.");
            Logger.statusUndecided("Configuration");
            ExceptionHandler.showStackTrace(e);
        }

        finally {
            Logger.decreaseIndent();
        }

        return false;
    }

    /**
     * Attempts a login without credentials on the remote MBeanServer. Success or failure is reported within
     * the status messages.
     *
     * @return true if unauthenticated access is possible
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

        catch (ApacheKarafException e) {
            Logger.printlnMixedYellow("- Remote MBean server", "requires authentication", "(Apache Karaf)");
            Logger.statusOk();

            Logger.decreaseIndent();
            Logger.lineBreak();

            return enumKaraf();
        }

        catch (AuthenticationException e) {

            if (e instanceof MissingCredentialsException) {
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
     * Attempts to login using Apache Karaf default credentials.
     *
     * @return true if Apache Karaf default credentials work on the endpoint
     */
    public boolean enumKaraf()
    {
        Map<String, Object> env = ArgumentHandler.getEnv("karaf", "karaf");

        Logger.printlnBlue("Checking for Apache Karaf default credentials:");
        Logger.lineBreak();
        Logger.increaseIndent();

        try {
            MBeanServerConnection conn = PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);

            Logger.printlnMixedYellow("- Login with default credentials", "karaf:karaf", "was successful.");
            Logger.statusVulnerable();

            client = new MBeanServerClient(conn);
            return true;
        }

        catch (AuthenticationException e) {

            if (e instanceof WrongCredentialsException) {
                Logger.printlnMixedYellow("- Default credentials", "are not", "in use.");
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
     * @return true if unauthenticated access is possible
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
            Logger.printlnMixedYellow("- JMXMP serial check is","work in progress", "but endpoints are usually vulnerable.");
            Logger.statusUndecided("Configuration");
            Logger.decreaseIndent();
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
    public Set<ObjectInstance> enumMBeans()
    {
        if (client == null)
            return new HashSet<ObjectInstance>();

        Logger.printlnBlue("Checking available MBeans:");
        Logger.lineBreak();
        Logger.increaseIndent();

        Set<ObjectInstance> mbeans = client.getMBeans();

        List<String> classNames = mbeans.stream().map(i -> i.getClassName()).collect(Collectors.toList());
        classNames.removeAll(Arrays.asList(ArgumentHandler.getInstance().getFromConfig("defaultMBeans").split(" ")));

        Logger.printlnMixedYellowFirst("- " + mbeans.size(), "MBeans are currently registred on the MBean server.");

        if( classNames.size() == 0 )
        {
            Logger.printlnMixedBlue("  Found", "0", "non default MBeans.");
        }

        else
        {
            Logger.printlnMixedBlue("  Listing", String.valueOf(classNames.size()), "non default MBeans:");

            for(ObjectInstance instance : mbeans)
            {
                if (!classNames.contains(instance.getClassName()))
                    continue;

                Logger.printMixedYellow("  -", instance.getClassName(), "");
                Logger.printlnPlainBlue("(" + instance.getObjectName().toString() + ")");
            }
        }

        Logger.decreaseIndent();
        return mbeans;
    }

    /**
     * Checks whether the targeted JMX server requires credentials.
     *
     * @return true if credentials are required
     */
    public boolean requriesLogin()
    {
        Map<String, Object> env = ArgumentHandler.getEnv(null, null);

        try {
            PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);
            return false;
        }

        catch(AuthenticationException e) {

            if(e instanceof MissingCredentialsException)
                return true;

            if(e instanceof SaslProfileException)
            {
                Logger.printlnMixedBlue("Caught", "SaslProfileException", "during login attempt.");
                Logger.printlnMixedYellow("Use the", "--sasl", "option to specify a matching SASL profile.");
                ExceptionHandler.showStackTrace(e);
                Utils.exit();
            }

            ExceptionHandler.unexpectedException(e, "login", "attempt", true);
        }

        return true;
    }

    /**
     * Performs a login attempt with a dummy username and a dummy password. The JMX service is expected to
     * raise a WrongCredentialsException. If this is not the case, there is probably a connection error.
     */
    public void checkLoginFormat()
    {
        Map<String, Object> env = ArgumentHandler.getEnv("beanshooter", "beanshooter");

        try {
            PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);
        }

        catch(AuthenticationException e) {

            if(e instanceof WrongCredentialsException)
                return;

            if(e instanceof MismatchedURIException)
            {
                Logger.printlnMixedYellow("Caught", "MismatchedURIException", "during login attempt.");
                Logger.printlnMixedBlueFirst("Digest authentication", "requires the correct hostname to be used.");
                Logger.printlnMixedBlue("Original error message:", e.getMessage());
                ExceptionHandler.showStackTrace(e);
                Utils.exit();
            }

            if(e instanceof SaslProfileException)
            {
                Logger.printlnMixedBlue("Caught", "SaslProfileException", "during login attempt.");
                Logger.printlnMixedYellow("Use the", "--sasl", "option to specify a matching SASL profile.");
                ExceptionHandler.showStackTrace(e);
                Utils.exit();
            }

            ExceptionHandler.unexpectedException(e, "login", "attempt", true);
        }
    }
}
