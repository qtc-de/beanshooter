package de.qtc.beanshooter.mbean.hotspot;

import java.lang.reflect.Proxy;

import javax.management.MBeanException;
import javax.management.openmbean.CompositeData;

import com.sun.management.VMOption;

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
@SuppressWarnings("restriction")
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private final HotSpotDiagnosticMXBean diagnostic;

    /**
     * Creates the dispatcher that operates on the MLet MBean.
     */
    public Dispatcher()
    {
        super(MBean.HOTSPOT_DIAGNOSTIC);

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        diagnostic = (HotSpotDiagnosticMXBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                  new Class<?>[] { HotSpotDiagnosticMXBean.class },
                                                  invo);
    }

    public void dumpHeap()
    {
        String filename = ArgumentHandler.require(HotSpotDiagnosticOption.DUMP_FILE);
        boolean live = HotSpotDiagnosticOption.LIVE.getBool();

        try
        {
            diagnostic.dumpHeap(filename, live);
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "creating", "heapdump", true);
        }
    }

    public void listOptions()
    {
        try
        {
            CompositeData[] options = (CompositeData[]) diagnostic.getAttribute("DiagnosticOptions");

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

    public void getOption()
    {
        String vmOption = ArgumentHandler.require(HotSpotDiagnosticOption.OPTION_NAME);

        try
        {
            VMOption option = diagnostic.getVMOption(vmOption);

            Logger.printlnYellow(option.getName());
            Logger.printlnMixedBlue("Value:", option.getValue());
            Logger.printlnMixedBlue("Writable:", String.valueOf(option.isWriteable()));
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "getting", "VMOption", true);
        }
    }

    public void setOption()
    {
        String vmOption = ArgumentHandler.require(HotSpotDiagnosticOption.OPTION_NAME);
        String optionValue = ArgumentHandler.require(HotSpotDiagnosticOption.OPTION_VALUE);

        try
        {
            diagnostic.setVMOption(vmOption, optionValue);
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "setting", "VMOption", true);
        }
    }
}
