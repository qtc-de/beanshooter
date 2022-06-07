package de.qtc.beanshooter.mbean.diagnostic;

import java.lang.reflect.Proxy;

import javax.management.MBeanException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.mbean.MBeanInvocationHandler;

/**
 * Dispatcher class for MLet MBean operations. Implements operations that are supported
 * by the MLet MBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private final DiagnosticCommandMBean diagnostic;

    /**
     * Creates the dispatcher that operates on the MLet MBean.
     */
    public Dispatcher()
    {
        super(MBean.DIAGNOSTIC_COMMAND);

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        diagnostic = (DiagnosticCommandMBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                  new Class<?>[] { DiagnosticCommandMBean.class },
                                                  invo);
    }

    public void readFile()
    {
        String filename = ArgumentHandler.require(DiagnosticCommandOption.FILENAME);

        try
        {
            String output = diagnostic.compilerDirectivesAdd(new String[] { filename });
            Logger.printlnBlue(output);
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "creating", "heapdump", true);
        }
    }

    public void loadLibrary()
    {
        String filename = ArgumentHandler.require(DiagnosticCommandOption.LOAD);

        try
        {
            String output = diagnostic.jvmtiAgentLoad(new String[] { filename });
            Logger.printlnBlue(output);
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "creating", "heapdump", true);
        }
    }

    public void setLogfile()
    {
        String filename = ArgumentHandler.require(DiagnosticCommandOption.FILENAME);
        filename = "output=" + filename;

        try
        {
            diagnostic.vmLog(new String[] { filename });
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "creating", "heapdump", true);
        }
    }

    public void disableLogging()
    {
        try
        {
            diagnostic.vmLog(new String[] { "disable" });
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "creating", "heapdump", true);
        }
    }
}