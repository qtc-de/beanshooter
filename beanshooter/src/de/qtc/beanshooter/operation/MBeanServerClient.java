package de.qtc.beanshooter.operation;

import java.io.IOException;
import java.util.Set;

import javax.management.InstanceAlreadyExistsException;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectInstance;
import javax.management.ObjectName;
import javax.management.ReflectionException;

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

    public boolean isRegistered(ObjectName name)
    {
        boolean result = false;

        try {

            if( conn.isRegistered(name) )
                result = true;

        } catch (IOException e) {
            e.printStackTrace();
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
        String className = mBeanClassName.substring(mBeanClassName.lastIndexOf(".") + 1);
        Logger.printlnMixedYellow("Deplyoing MBean:", className);

        try {

            if( conn.isRegistered(mBeanObjectName) )
            {
                Logger.printlnMixedBlue("MBean with object name", mBeanObjectName.toString(), "is already deployed.");
                return;
            }

            conn.createMBean(mBeanClassName, mBeanObjectName);

        } catch (InstanceAlreadyExistsException e) {
            Logger.printlnMixedYellowFirst(className, "is already deployed.");
            return;

        } catch (javax.management.ReflectionException e) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof ClassNotFoundException) {

                if( jarFile != null ) {

                    Logger.lineBreak();
                    Logger.increaseIndent();

                    Logger.println("MBean class is not known to the server.");

                    if( BeanshooterOption.DEPLOY_STAGER_URL.isNull() )
                    {
                        Logger.printlnMixedYellow("You can use the", BeanshooterOption.DEPLOY_STAGER_URL.getName(), "option to load the MBean from remote.");
                        Utils.exit();
                    }

                    DynamicMBean mbean = new DynamicMBean(mBeanObjectName, mBeanClassName, jarFile);

                    Dispatcher mLetDispatcher = new Dispatcher();
                    mLetDispatcher.loadMBeanFromURL(mbean, BeanshooterOption.DEPLOY_STAGER_URL.getValue());

                    Logger.decreaseIndent();

                } else
                    ExceptionHandler.unexpectedException(e, "deploy", "MBean", true);
            }

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "registering", "MLet", true);
        }

        Logger.printlnMixedBlue("MBean with object name", mBeanObjectName.toString(), "was successfully deployed.");
    }

    /**
     * Unregisters an MBean from the remote MBeanServer.
     *
     * @param objectName ObjectName of the MBean to unregister
     */
    public void unregisterMBean(ObjectName objectName)
    {
        Logger.printlnMixedYellow("Removing MBean with ObjectName", objectName.toString(), "from the MBeanServer.");

        try {
            conn.unregisterMBean(objectName);

        } catch (InstanceNotFoundException e) {

        } catch (MBeanRegistrationException e) {
            //TODO
            e.printStackTrace();

        } catch (IOException e) {
            //TODO
            e.printStackTrace();
        }

        Logger.println("MBean was successfully removed.");
    }

    public Set<ObjectInstance> getMBeans()
    {
        try {
            return conn.queryMBeans(null, null);

        } catch (IOException e) {
            // TODO
            e.printStackTrace();
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
     * @param args arguments to use for the call
     * @return return value of the MBean call.
     * @throws InstanceNotFoundException
     * @throws MBeanException
     * @throws ReflectionException
     * @throws IOException
     */
    public Object invoke(ObjectName name, String methodName, Object... args) throws  IOException, MBeanException, ReflectionException
    {
        String[] argumentTypes = new String[args.length];

        for(int ctr = 0; ctr < args.length; ctr++)
            argumentTypes[ctr] = args[ctr].getClass().getName();

        Object result = null;

        try {
            result = conn.invoke(name, methodName, args, argumentTypes);

        } catch( InstanceNotFoundException e ) {
            Logger.eprintlnMixedYellow("Caught unexpected", "InstanceNotFoundException", "while calling invoke.");
            Logger.eprintlnMixedBlue("The specified MBean", name.toString(), "does probably not exist on the endpoint.");
            Utils.exit();
        }

        return result;
    }
}
