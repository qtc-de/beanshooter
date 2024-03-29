package de.qtc.beanshooter.operation;

import java.io.IOException;
import java.lang.reflect.UndeclaredThrowableException;
import java.rmi.UnmarshalException;
import java.util.Set;

import javax.management.Attribute;
import javax.management.AttributeNotFoundException;
import javax.management.InstanceAlreadyExistsException;
import javax.management.InstanceNotFoundException;
import javax.management.IntrospectionException;
import javax.management.InvalidAttributeValueException;
import javax.management.MBeanException;
import javax.management.MBeanInfo;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.management.RuntimeOperationsException;

import org.jolokia.client.exception.J4pRemoteException;
import org.jolokia.client.exception.UncheckedJmxAdapterException;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.DynamicMBean;
import de.qtc.beanshooter.mbean.mlet.Dispatcher;
import de.qtc.beanshooter.utils.Utils;

/**
 * The MBeanServerClient is basically a wrapper around an MBeanServerConnection. It implements
 * wrappers around the methods defined in MBeanServerConnection and adds some additional functionality.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MBeanServerClient {

    private final MBeanServerConnection conn;

    public MBeanServerClient(MBeanServerConnection conn)
    {
        this.conn = conn;
    }

    /**
     * Check whether the specified ObjectName is registered on the MBeanServer.
     *
     * @param name ObjectName to check for
     * @return True of the ObjectName is registered, false otherwise.
     */
    public boolean isRegistered(ObjectName name)
    {
        boolean result = false;

        try
        {
            if( conn.isRegistered(name) )
                result = true;
        }

        catch (IOException e)
        {
            ExceptionHandler.unexpectedException(e, "checking", "registration status", false);
        }

        return result;
    }

    /**
     * Deploys the specified MBean. If the load parameter is set to true, the MBean will be loaded
     * using getMBeansFromURL if it is not known to the MBEanServer.
     *
     * @param mBeanClassName class that is implemented by the MBean
     * @param mBeanObjectName objectName implemented by the MBean
     * @param jarFile path to a jar file for remote deployments (null if not desired)
     */
    public void deployMBean(String mBeanClassName, ObjectName mBeanObjectName, String jarFile)
    {
        deployMBean(mBeanClassName, mBeanObjectName, jarFile, null, null);
    }

    /**
     * Deploys the specified MBean. If the load parameter is set to true, the MBean will be loaded
     * using getMBeansFromURL if it is not known to the MBEanServer.
     *
     * @param mBeanClassName class that is implemented by the MBean
     * @param mBeanObjectName objectName implemented by the MBean
     * @param jarFile path to a jar file for remote deployments (null if not desired)
     * @param if a specific constructor should be used, define its parameters here
     * @param if a specific constructor should be used, define its signature here
     */
    public void deployMBean(String mBeanClassName, ObjectName mBeanObjectName, String jarFile, Object[] params, String[] signature)
    {
        String className = mBeanClassName.substring(mBeanClassName.lastIndexOf(".") + 1);
        Logger.printlnMixedYellow("Deplyoing MBean:", className);

        try {

            if (conn.isRegistered(mBeanObjectName))
            {
                Logger.printlnMixedBlue("MBean with object name", mBeanObjectName.toString(), "is already deployed.");
                return;
            }

            if (params == null || signature == null)
                conn.createMBean(mBeanClassName, mBeanObjectName);

            else
                conn.createMBean(mBeanClassName, mBeanObjectName, params, signature);
        }

        catch (InstanceAlreadyExistsException e)
        {
            Logger.printlnMixedYellowFirst(className, "is already deployed.");
            return;
        }

        catch (UnsupportedOperationException e)
        {
            Logger.lineBreak();

            if (BeanshooterOption.CONN_JOLOKIA.getBool())
                ExceptionHandler.jolokiaCreateMBean(e);

            else
                throw e;
        }

        catch (javax.management.ReflectionException | UndeclaredThrowableException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof ClassNotFoundException)
            {
                if (jarFile != null)
                {
                    Logger.lineBreak();
                    Logger.increaseIndent();

                    Logger.println("MBean class is not known by the server.");

                    if (BeanshooterOption.DEPLOY_STAGER_URL.isNull())
                    {
                        Logger.eprintlnMixedYellow("Use the", BeanshooterOption.DEPLOY_STAGER_URL.getName(), "option to load the MBean from remote.");
                        Utils.exit(e);
                    }

                    DynamicMBean mbean = new DynamicMBean(mBeanObjectName, mBeanClassName, jarFile);

                    Dispatcher mLetDispatcher = new Dispatcher();
                    mLetDispatcher.loadMBeanFromURL(mbean, BeanshooterOption.DEPLOY_STAGER_URL.getValue());

                    Logger.decreaseIndent();
                }

                else
                {
                    Logger.lineBreak();
                    Logger.eprintlnMixedBlue("The specified class", className, "is not known by the server.");
                    Logger.eprintMixedYellow("Use the", "--jar-file");
                    Logger.eprintlnPlainMixedYellow(" and", "--stager-url", "options to provide an implementation.");
                    Utils.exit(e);
                }
            }

            else
            {
                ExceptionHandler.unexpectedException(e, "deploying", "MBean", true);
            }
        }

        catch (SecurityException e)
        {
            Logger.lineBreak();

            if( e.getMessage().contains("Invalid access level") )
                ExceptionHandler.insufficientPermission(e, "registering MBean", true);

            else if( e.getMessage().contains("Creating an MBean that is a ClassLoader is forbidden") )
                ExceptionHandler.protectedEndpoint(e, "registering MBean", true);

            else
                ExceptionHandler.unexpectedException(e, "registering", "MBean", true);
        }

        catch (UnmarshalException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof ClassNotFoundException)
            {
                String missingClass = t.getMessage().split(" ")[0];
                Logger.eprintlnMixedYellow("Caught", "ClassNotFoundException", "during MBean deployment.");
                Logger.eprintlnMixedBlue("The class", missingClass, "is not known by the server.");
                Utils.exit(e);
            }

            ExceptionHandler.unexpectedException(e, "registering", "MBean", true);
        }

        catch (Exception e)
        {
            ExceptionHandler.unexpectedException(e, "registering", "MBean", true);
        }

        Logger.printMixedBlue("MBean with object name", mBeanObjectName.toString(), "was ");
        Logger.printlnPlainMixedYellowFirst("successfully",  "deployed.");
    }

    /**
     * Unregisters an MBean from the remote MBeanServer.
     *
     * @param objectName ObjectName of the MBean to unregister
     */
    public void unregisterMBean(ObjectName objectName)
    {
        Logger.printlnMixedYellow("Removing MBean with ObjectName", objectName.toString(), "from the MBeanServer.");

        try
        {
            conn.unregisterMBean(objectName);
        }

        catch (UnsupportedOperationException e)
        {
            if (BeanshooterOption.CONN_JOLOKIA.getBool())
                ExceptionHandler.jolokiaRemoveMBean(e);

            else
                throw e;
        }

        catch (InstanceNotFoundException e)
        {
            Logger.println("MBean is not registered. Nothing to do.");
            return;

        } catch (SecurityException e) {

            Logger.lineBreak();

            if( e.getMessage().contains("Invalid access level") )
                ExceptionHandler.insufficientPermission(e, "unregistering MBean", true);

            else
                ExceptionHandler.unexpectedException(e, "unregistering", "MBean", true);
        }

        catch (MBeanRegistrationException | IOException e)
        {
            ExceptionHandler.unexpectedException(e, "unregistering", "MBean", true);
        }

        Logger.println("MBean was successfully removed.");
    }

    /**
     * Obtain a set of MBeans registered on the remote server.
     *
     * @return set of ObjectInstance where each Instance represents an MBean on the server
     */
    public Set<ObjectInstance> getMBeans()
    {
        try
        {
            return conn.queryMBeans(null, null);
        }

        catch (IOException e)
        {
            ExceptionHandler.unexpectedException(e, "listing", "MBeans", true);
        }

        return null;
    }

    /**
     * Wrapper to invoke a function on an MBeanServerConnection. Automatically determines the required types
     * and makes invoking MBean functions a little bit less verbose.
     *
     * @param conn MBeanServerConnection to invoke the function on
     * @param name ObjectName of the MBean to invoke the function on
     * @param methodName function name to invoke
     * @param argTypes array of argument type names for the desired method
     * @param args arguments to use for the call
     * @return return value of the MBean call.
     * @throws InstanceNotFoundException
     * @throws MBeanException
     * @throws ReflectionException
     * @throws IOException
     */
    public Object invoke(ObjectName name, String methodName, String[] argTypes, Object... args) throws  IOException, MBeanException, ReflectionException
    {
        Object result = null;

        if (argTypes == null && args != null)
        {
            argTypes = new String[args.length];

            for (int ctr = 0; ctr < args.length; ctr++)
                argTypes[ctr] = args[ctr].getClass().getName();
        }

        try
        {
            result = conn.invoke(name, methodName, args, argTypes);
        }

        catch (InstanceNotFoundException e)
        {
            ExceptionHandler.handleInstanceNotFound(e, name.toString());
        }

        catch (ReflectionException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof java.lang.NoSuchMethodException)
                ExceptionHandler.noSuchMethod(e, methodName);

            throw e;
        }

        catch (SecurityException e)
        {
            String message = e.getMessage();

            if (message.contains("Access denied!"))
                ExceptionHandler.mBeanAccessDenied(e, name.toString(), methodName);

            else
                throw e;
        }

        catch (MBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);
            String message = t.getMessage();

            if (t instanceof J4pRemoteException && message.contains("javax.management.InstanceNotFoundException"))
                ExceptionHandler.handleInstanceNotFound(e, name.toString());

            throw e;
        }

        catch (RuntimeOperationsException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IllegalArgumentException)
            {
                String[] actualArgumentTypes = new String[args.length];

                for (int ctr = 0; ctr < args.length; ctr++)
                {
                    actualArgumentTypes[ctr] = args[ctr].getClass().getName();
                }

                Logger.eprintlnMixedYellow("Caught unexpected", "IllegalArgumentException", "while invoking the method.");
                Logger.eprintlnMixedBlue("The specified argument types:", String.join(", ", actualArgumentTypes));
                Logger.eprintlnMixedBlue("Do not match the expected argument types:", String.join(" ,", argTypes));
                Utils.exit(e);
            }

            throw e;
        }

        return result;
    }

    /**
     * Wrapper around the getAttribute function from the MBeanServerConnection.
     *
     * @param name ObjectName of the MBean to obtain the attribute from
     * @param attr the name of the attribute to obtain
     * @return attribute value
     * @throws MBeanException
     * @throws ReflectionException
     * @throws IOException
     */
    public Object getAttribute(ObjectName name, String attributeName) throws MBeanException, ReflectionException, IOException
    {
        try
        {
            return conn.getAttribute(name, attributeName);
        }

        catch (UncheckedJmxAdapterException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof J4pRemoteException)
            {
                String message = t.getMessage();

                if (message.contains("InstanceNotFoundException"))
                    ExceptionHandler.handleInstanceNotFound(e, name.toString());

                else if (message.contains("AttributeNotFoundException"))
                    ExceptionHandler.noSuchAttribute(e, attributeName);
            }

            throw e;
        }

        catch (InstanceNotFoundException e)
        {
            ExceptionHandler.handleInstanceNotFound(e, name.toString());
        }

        catch (AttributeNotFoundException e)
        {
            ExceptionHandler.noSuchAttribute(e, attributeName);
        }

        return null;
    }

    /**
     * Wrapper around the setAttribute function from the MBeanServerConnection.
     *
     * @param name ObjectName of the MBean to set the attribute on
     * @param attr the Attribute to set
     * @return attribute value
     * @throws MBeanException
     * @throws ReflectionException
     * @throws IOException
     */
    public void setAttribute(ObjectName name, Attribute attr) throws MBeanException, ReflectionException, IOException
    {
        try
        {
            conn.setAttribute(name, attr);
        }

        catch (UncheckedJmxAdapterException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof J4pRemoteException)
            {
                String message = t.getMessage();

                if (message.contains("InstanceNotFoundException"))
                    ExceptionHandler.handleInstanceNotFound(e, name.toString());

                else if (message.contains("AttributeNotFoundException"))
                    ExceptionHandler.noSuchAttribute(e, attr.getName());

                else if (message.contains("InvalidAttributeValueException"))
                {
                    Logger.eprintlnMixedYellow("Caught", "InvalidAttributeValueException", "while setting the attribute.");
                    Logger.eprintlnMixedBlue("The specified attribute value of class", attr.getValue().getClass().getName(), "is probably not compatible.");
                    Logger.eprintlnMixedYellow("You can use the", "--type", "option to specify a different type manually.");
                    Utils.exit(e);
                }
            }

            throw e;
        }

        catch (InstanceNotFoundException e)
        {
            ExceptionHandler.handleInstanceNotFound(e, name.toString());
        }

        catch (AttributeNotFoundException e)
        {
            ExceptionHandler.noSuchAttribute(e, attr.getName());
        }

        catch (InvalidAttributeValueException e)
        {
            Logger.eprintlnMixedYellow("Caught", "InvalidAttributeValueException", "while setting the attribute.");
            Logger.eprintlnMixedBlue("The specified attribute value of class", attr.getValue().getClass().getName(), "is probably not compatible.");
            Logger.eprintlnMixedYellow("You can use the", "--type", "option to specify a different type manually.");
            Utils.exit(e);
        }
    }

    /**
     * Wrapper around the getMBeanInfo function of the MBeanServerConnection.
     *
     * @param name ObjectName of the MBean to obtain the MBeanInfo from
     * @return obtained MBeanInfo
     */
    public MBeanInfo getMBeanInfo(ObjectName name)
    {
        try
        {
            return conn.getMBeanInfo(name);
        }

        catch (InstanceNotFoundException e)
        {
            ExceptionHandler.handleInstanceNotFound(e, name.toString());
        }

        catch (ReflectionException | IOException | IntrospectionException e)
        {
            ExceptionHandler.unexpectedException(e, "obtaining", "MBeanInfo", true);
        }

        return null;
    }

    /**
     * Obtain the underlying MBeanServerConnection object.
     *
     * @return MBeanServerConnection object that is used by the client
     */
    public MBeanServerConnection getConnection()
    {
        return this.conn;
    }
}
