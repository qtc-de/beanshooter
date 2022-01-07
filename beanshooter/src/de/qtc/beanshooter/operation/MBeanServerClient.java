package de.qtc.beanshooter.operation;

import java.io.IOException;

import javax.management.InstanceAlreadyExistsException;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanRegistrationException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.ReflectionException;

import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;

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
     * @param load whether to load the MBean from a stager server
     */
    public void deployMBean(String mBeanClassName, ObjectName mBeanObjectName, boolean load)
    {
        String className = mBeanClassName.substring(mBeanClassName.lastIndexOf(".") + 1);
        Logger.printlnMixedYellow("Deplyoing MBean:", className);

        try {
            if( conn.isRegistered(mBeanObjectName) )
                return;

            conn.createMBean(mBeanClassName, mBeanObjectName);

        } catch (InstanceAlreadyExistsException e) {
            return;

        } catch (javax.management.ReflectionException e) {

            Throwable t = ExceptionHandler.getCause(e);

            if( t instanceof ClassNotFoundException) {

                if( load ) {
                    Logger.lineBreak();
                    Logger.increaseIndent();
                    Logger.println("MBean class is not known to the server.");
                    MLetClient mLetClient = new MLetClient(this);
                    mLetClient.loadMBeanFromURL(mBeanClassName, mBeanObjectName, Option.require(Option.DEPLOY_STAGER_URL));
                    Logger.decreaseIndent();

                } else
                    ExceptionHandler.unexpectedException(e, "deploy", "MBean", true);
            }

        } catch (Exception e) {
            ExceptionHandler.unexpectedException(e, "registering", "MLet", true);
        }
    }

    /**
     * Unregisters an MBean from the remote MBeanServer.
     *
     * @param objectName ObjectName of the MBean to unregister
     */
    public void unregisterMBean(ObjectName objectName)
    {
        try {

            conn.unregisterMBean(objectName);

        } catch (InstanceNotFoundException e) {
            return;

        } catch (MBeanRegistrationException e) {

            e.printStackTrace();

        } catch (IOException e) {
            e.printStackTrace();
        }
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
    public Object invoke(ObjectName name, String methodName, Object... args) throws InstanceNotFoundException, MBeanException, ReflectionException, IOException
    {
        String[] argumentTypes = new String[args.length];

        for(int ctr = 0; ctr < args.length; ctr++)
            argumentTypes[ctr] = args[ctr].getClass().getName();

        return conn.invoke(name, methodName, args, argumentTypes);
    }
}
