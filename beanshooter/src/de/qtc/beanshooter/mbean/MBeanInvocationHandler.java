package de.qtc.beanshooter.mbean;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MBeanServerConnection;
import javax.management.ObjectName;
import javax.management.ReflectionException;
import javax.management.RuntimeMBeanException;
import javax.management.openmbean.CompositeData;

import org.jolokia.client.exception.J4pRemoteException;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.OpenTypeException;
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
public class MBeanInvocationHandler implements InvocationHandler
{
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

        try
        {
            if( method.getName().equals("getAttribute") )
                retValue = conn.getAttribute(objName, (String) args[0]);

            else
                retValue = conn.invoke(objName, method.getName(), args, Utils.typesToString(method.getParameterTypes()));
        }

        catch (InstanceNotFoundException e)
        {
            Logger.resetIndent();

            if(Logger.printCount != 0)
                Logger.lineBreak();

            ExceptionHandler.handleInstanceNotFound(e, objName.toString());
        }

        catch (ReflectionException e)
        {
            Logger.resetIndent();

            if(Logger.printCount != 0)
                Logger.lineBreak();

            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof java.lang.NoSuchMethodException)
                ExceptionHandler.noSuchMethod(e, Utils.getMethodString(method));

            else
                ExceptionHandler.unexpectedException(e, "invoke", "operation", true);
        }

        catch (SecurityException e)
        {
            String message = e.getMessage();

            if (message.contains("Access denied!"))
                ExceptionHandler.mBeanAccessDenied(e, objName.toString(), method.getName());

            else
                throw e;
        }

        catch (MBeanException e)
        {
            Throwable cause = ExceptionHandler.getCause(e);

            if (cause instanceof J4pRemoteException)
            {
                String message = cause.getMessage();
                String[] split = message.split(":");

                String exceptionName = split[1].trim();
                String exceptionMessage = split[2].trim();

                try
                {
                    Class<?> exceptionClass = Class.forName(exceptionName);
                    Constructor<?> constr = exceptionClass.getDeclaredConstructor(new Class<?>[] { String.class });

                    if (Exception.class.isAssignableFrom(exceptionClass))
                    {
                        if (exceptionName.startsWith("java.lang.Illegal"))
                            throw new RuntimeMBeanException((RuntimeException)constr.newInstance(exceptionMessage), "Forwarded Jolokia Exception");

                        else
                            throw new MBeanException((Exception)constr.newInstance(exceptionMessage), "Forwarded Jolokia Exception");
                    }
                }

                catch (ClassNotFoundException | ClassCastException | NoSuchMethodException | SecurityException e2){}

                Logger.eprintlnMixedYellow("Caught", "J4pRemoteException", "during MBean method invocation.");
                Logger.eprintlnMixedBlue("Jolokia reported:", message);

                Utils.exit();
            }

            else
                throw e;
        }

        return openTypeConverter(method.getReturnType(), retValue);
    }

    /**
     * When MBeans are invoked via Jolokia, their return type sometimes differ from the regular
     * interface definition. E.g. an MBean interface that defines Set<Object> as return type may
     * return CompositeData[] when invoked via Jolokia.
     *
     * To be honest, I do not have a full understanding of this whole OpenType mechanic and I'm not
     * sure whether there isn't a smarter way to do this, but we use this function to adapt the return
     * type for cases that are known to cause problems.
     *
     * @param expected  the expected return type defined by the MBean interface
     * @param value  the actual return value
     * @return if value matches the expected type, return value. Otherwise, convert and return it
     * @throws Throwable
     */
    private static Object openTypeConverter(Class<?> expected, Object value) throws Throwable
    {
        // This case was observed when running MLet getMBeansFromURL, which returns a Set<Object>
        // by definition, but returns CompositeData[] when obtained from Jolokia
        if (expected == Set.class && (value instanceof CompositeData[]))
        {
            Set<Object> retSet = new HashSet<Object>();

            for(CompositeData compItem : (CompositeData[])value)
                for (Object item : compItem.values())
                    if ((item instanceof String) && item.toString().contains("Exception"))
                        retSet.add(new OpenTypeException(item.toString()));

            return retSet;
        }

        // This case was observed when invoking the exec methods from the TonkaBean. The interface
        // defines the return type as byte[], but Jolokia returns Long[]
        if (expected == byte[].class && (value instanceof Long[]))
        {
            Long[] values = (Long[])value;

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);

            for (int ctr = 0; ctr < values.length; ctr++)
                dos.writeLong(values[ctr]);

            return baos.toByteArray();
        }

        return value;
    }
}
