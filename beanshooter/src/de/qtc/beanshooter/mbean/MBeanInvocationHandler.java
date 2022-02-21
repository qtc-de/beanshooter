package de.qtc.beanshooter.mbean;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.utils.Utils;

/**
 * The MBeanInvocationHandler class can be used to invoke MBean methods in a convenient way. AS the name suggests,
 * it implements the InvocationHandler interface and can be use to create a dynamic Proxy for an interface exposed
 * by an MBean. All method invocations are passed to the MBeanServerConnection that needs to be specified during
 * creation of the MBeanInvocationHandler.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MBeanInvocationHandler implements InvocationHandler {

    private final MBeanServerConnection conn;
    private final ObjectName objName;

    /**
     * Creating an MBeanInvocationHandler requires the ObjectName of the MBean the InvocationHandler is operating
     * on. Furthermore, a MBeanServerConnection is required where the calls are dispatched.
     *
     * @param objName ObjectName of the targeted MBean
     * @param conn MBeanServerConnection to pass calls to
     */
    public MBeanInvocationHandler(ObjectName objName, MBeanServerConnection conn)
    {
        this.objName = objName;
        this.conn = conn;
    }

    /**
     * Method invocations on the MBeanInvocationHandler are simply passed to the underlying MBeanServerConnection
     * object.
     */
    @Override
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable
    {
        Object retValue = null;

        try {
            if( method.getName().equals("getAttribute") )
                retValue = conn.getAttribute(objName, (String) args[0]);

            else
                retValue = conn.invoke(objName, method.getName(), args, Utils.typesToString(method.getParameterTypes()));

        } catch( InstanceNotFoundException e ) {
            Logger.resetIndent();

            if(Logger.printCount != 0)
                Logger.lineBreak();

            ExceptionHandler.handleInstanceNotFound(e, objName.toString());
        }

        return retValue;
    }
}