package de.qtc.beanshooter.mbean.hotspot;

import java.io.IOException;
import java.lang.reflect.Proxy;

import javax.management.MBeanException;
import javax.management.RuntimeMBeanException;
import javax.management.openmbean.CompositeData;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.mbean.MBeanInvocationHandler;

/**
 * Dispatcher class for HotSpotDiagnostic MXBean operations. Implements operations that are supported
 * by the HotSpotDiagnosticMXBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private final HotSpotDiagnosticMXBean diagnostic;

    /**
     * Creates the dispatcher that operates on the HotSpotDiagnosticMXBean.
     */
    public Dispatcher()
    {
        super(MBean.HOTSPOT_DIAGNOSTIC);

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        diagnostic = (HotSpotDiagnosticMXBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                  new Class<?>[] { HotSpotDiagnosticMXBean.class },
                                                  invo);
    }

    /**
     * Saves a heapdump to a file on the JMX server.
     */
    public void dumpHeap()
    {
        String filename = ArgumentHandler.require(HotSpotDiagnosticOption.DUMP_FILE);
        boolean live = HotSpotDiagnosticOption.LIVE.getBool();

        try
        {
            diagnostic.dumpHeap(filename, live);
            Logger.printlnMixedYellow("Heapdump file", filename, "was created successfully.");
        }

        catch (MBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IOException)
            {
                Logger.eprintlnMixedYellow("Saving heapdump on the server caused an", "IOException.");
                ExceptionHandler.handleFileWrite(t, filename, true);
            }

            ExceptionHandler.unexpectedException(e, "creating", "heapdump", true);
        }

        catch (RuntimeMBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IllegalArgumentException && t.getMessage().contains("must have .hprof extention"))
                Logger.eprintlnMixedYellow("Heapdump file must have", ".hrpof", "extention.");

            else
                ExceptionHandler.unexpectedException(e, "creating", "heapdump", true);
        }
    }

    /**
     * List available diagnostic options on the JMX server.
     */
    public void listOptions()
    {
        try
        {
            CompositeData[] options = (CompositeData[])diagnostic.getAttribute("DiagnosticOptions");

            for (CompositeData option : options)
            {
                Logger.printMixedBlueFirst(option.get("name").toString(), "(");
                Logger.printPlainMixedBlue("value =", option.get("value").toString());
                Logger.printPlainMixedBlue(", writable =", option.get("writeable").toString());
                Logger.printlnPlain(")");
            }
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "listing", "diagnostic options", true);
        }
    }

    /**
     * Get the current value of a specific option.
     */
    public void getOption()
    {
        String vmOption = ArgumentHandler.require(HotSpotDiagnosticOption.OPTION_NAME);

        try
        {
            CompositeData option = diagnostic.getVMOption(vmOption);

            Logger.printlnMixedYellow("Name:", String.valueOf(option.get("name")));
            Logger.printlnMixedBlue("Value:", String.valueOf(option.get("value")));
            Logger.printlnMixedBlue("Writable:", String.valueOf(option.get("writeable")));
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "getting", "VMOption", true);
        }

        catch (RuntimeMBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof IllegalArgumentException && t.getMessage().contains("does not exist"))
                Logger.eprintlnMixedYellow("A VMOption with name", vmOption, "does not exist on the remote server.");

            else
                ExceptionHandler.unexpectedException(e, "getting", "VMOption", true);
        }
    }

    /**
     * Set the value of a specific option.
     */
    public void setOption()
    {
        String vmOption = ArgumentHandler.require(HotSpotDiagnosticOption.OPTION_NAME);
        String optionValue = ArgumentHandler.require(HotSpotDiagnosticOption.OPTION_VALUE);

        try
        {
            diagnostic.setVMOption(vmOption, optionValue);
            Logger.printlnBlue("Option was set successfully.");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "setting", "VMOption", true);
        }

        catch (RuntimeMBeanException e)
        {
            Throwable t = ExceptionHandler.getThrowable("IllegalArgumentException", e);

            if (t != null)
            {
                String message = t.getMessage();

                if (message.contains("does not exist"))
                    Logger.eprintlnMixedYellow("A VMOption with name", vmOption, "does not exist on the remote server.");

                else if (message.contains("Invalid value") || message.contains("error: "))
                {
                    Logger.eprintlnMixedYellow("The specified value", optionValue, "is invalid.");
                    Logger.eprintlnBlue(message);
                }

                else
                    ExceptionHandler.unexpectedException(e, "setting", "VMOption", true);
            }

            else
                ExceptionHandler.unexpectedException(e, "setting", "VMOption", true);
        }
    }
}
