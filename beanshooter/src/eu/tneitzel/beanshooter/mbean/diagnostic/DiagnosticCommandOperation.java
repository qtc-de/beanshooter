package eu.tneitzel.beanshooter.mbean.diagnostic;

import java.lang.reflect.Method;

import eu.tneitzel.beanshooter.cli.Operation;
import eu.tneitzel.beanshooter.cli.Option;
import eu.tneitzel.beanshooter.exceptions.ExceptionHandler;
import eu.tneitzel.beanshooter.operation.BeanshooterOption;

/**
 * The DiagnosticCommandOperation enum contains operations that are available on a deployed DiagnosticCommand MBean.
 * Furthermore, it defines the options that are available for the corresponding operations.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum DiagnosticCommandOperation implements Operation
{
    READ("readFile", "use addCompilerDirective to read a file", new Option[] {
            BeanshooterOption.GLOBAL_CONFIG,
            BeanshooterOption.GLOBAL_VERBOSE,
            BeanshooterOption.GLOBAL_PLUGIN,
            BeanshooterOption.GLOBAL_NO_COLOR,
            BeanshooterOption.GLOBAL_STACK_TRACE,
            BeanshooterOption.TARGET_HOST,
            BeanshooterOption.TARGET_PORT,
            BeanshooterOption.TARGET_BOUND_NAME,
            BeanshooterOption.TARGET_OBJID_SERVER,
            BeanshooterOption.TARGET_OBJID_CONNECTION,
            BeanshooterOption.CONN_FOLLOW,
            BeanshooterOption.CONN_SSL,
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_JOLOKIA,
            BeanshooterOption.CONN_JOLOKIA_ENDPOINT,
            BeanshooterOption.CONN_JOLOKIA_PROXY,
            BeanshooterOption.CONN_JOLOKIA_PROXY_USER,
            BeanshooterOption.CONN_JOLOKIA_PROXY_PASS,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.CONN_JNDI,
            DiagnosticCommandOption.FILENAME,
            DiagnosticCommandOption.RAW,
    }),

    LOAD("loadLibrary", "load a shared library", new Option[] {
            BeanshooterOption.GLOBAL_CONFIG,
            BeanshooterOption.GLOBAL_VERBOSE,
            BeanshooterOption.GLOBAL_PLUGIN,
            BeanshooterOption.GLOBAL_NO_COLOR,
            BeanshooterOption.GLOBAL_STACK_TRACE,
            BeanshooterOption.TARGET_HOST,
            BeanshooterOption.TARGET_PORT,
            BeanshooterOption.TARGET_BOUND_NAME,
            BeanshooterOption.TARGET_OBJID_SERVER,
            BeanshooterOption.TARGET_OBJID_CONNECTION,
            BeanshooterOption.CONN_FOLLOW,
            BeanshooterOption.CONN_SSL,
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_JOLOKIA,
            BeanshooterOption.CONN_JOLOKIA_ENDPOINT,
            BeanshooterOption.CONN_JOLOKIA_PROXY,
            BeanshooterOption.CONN_JOLOKIA_PROXY_USER,
            BeanshooterOption.CONN_JOLOKIA_PROXY_PASS,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.CONN_JNDI,
            DiagnosticCommandOption.LIBRARY_PATH,
    }),

    LOGFILE("setLogfile", "set the log location of the Java VM", new Option[] {
            BeanshooterOption.GLOBAL_CONFIG,
            BeanshooterOption.GLOBAL_VERBOSE,
            BeanshooterOption.GLOBAL_PLUGIN,
            BeanshooterOption.GLOBAL_NO_COLOR,
            BeanshooterOption.GLOBAL_STACK_TRACE,
            BeanshooterOption.TARGET_HOST,
            BeanshooterOption.TARGET_PORT,
            BeanshooterOption.TARGET_BOUND_NAME,
            BeanshooterOption.TARGET_OBJID_SERVER,
            BeanshooterOption.TARGET_OBJID_CONNECTION,
            BeanshooterOption.CONN_FOLLOW,
            BeanshooterOption.CONN_SSL,
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_JOLOKIA,
            BeanshooterOption.CONN_JOLOKIA_ENDPOINT,
            BeanshooterOption.CONN_JOLOKIA_PROXY,
            BeanshooterOption.CONN_JOLOKIA_PROXY_USER,
            BeanshooterOption.CONN_JOLOKIA_PROXY_PASS,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.CONN_JNDI,
            DiagnosticCommandOption.FILENAME,
    }),

    NOLOG("disableLogging", "disable logging of the Java VM", new Option[] {
            BeanshooterOption.GLOBAL_CONFIG,
            BeanshooterOption.GLOBAL_VERBOSE,
            BeanshooterOption.GLOBAL_PLUGIN,
            BeanshooterOption.GLOBAL_NO_COLOR,
            BeanshooterOption.GLOBAL_STACK_TRACE,
            BeanshooterOption.TARGET_HOST,
            BeanshooterOption.TARGET_PORT,
            BeanshooterOption.TARGET_BOUND_NAME,
            BeanshooterOption.TARGET_OBJID_SERVER,
            BeanshooterOption.TARGET_OBJID_CONNECTION,
            BeanshooterOption.CONN_FOLLOW,
            BeanshooterOption.CONN_SSL,
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_JOLOKIA,
            BeanshooterOption.CONN_JOLOKIA_ENDPOINT,
            BeanshooterOption.CONN_JOLOKIA_PROXY,
            BeanshooterOption.CONN_JOLOKIA_PROXY_USER,
            BeanshooterOption.CONN_JOLOKIA_PROXY_PASS,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.CONN_JNDI,
    }),

    CMDLINE("getCommandLine", "get the Java virtual machine command line", new Option[] {
            BeanshooterOption.GLOBAL_CONFIG,
            BeanshooterOption.GLOBAL_VERBOSE,
            BeanshooterOption.GLOBAL_PLUGIN,
            BeanshooterOption.GLOBAL_NO_COLOR,
            BeanshooterOption.GLOBAL_STACK_TRACE,
            BeanshooterOption.TARGET_HOST,
            BeanshooterOption.TARGET_PORT,
            BeanshooterOption.TARGET_BOUND_NAME,
            BeanshooterOption.TARGET_OBJID_SERVER,
            BeanshooterOption.TARGET_OBJID_CONNECTION,
            BeanshooterOption.CONN_FOLLOW,
            BeanshooterOption.CONN_SSL,
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_JOLOKIA,
            BeanshooterOption.CONN_JOLOKIA_ENDPOINT,
            BeanshooterOption.CONN_JOLOKIA_PROXY,
            BeanshooterOption.CONN_JOLOKIA_PROXY_USER,
            BeanshooterOption.CONN_JOLOKIA_PROXY_PASS,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.CONN_JNDI,
    }),

    PROPS("getSystemProperties", "get Java virtual machine System properties", new Option[] {
            BeanshooterOption.GLOBAL_CONFIG,
            BeanshooterOption.GLOBAL_VERBOSE,
            BeanshooterOption.GLOBAL_PLUGIN,
            BeanshooterOption.GLOBAL_NO_COLOR,
            BeanshooterOption.GLOBAL_STACK_TRACE,
            BeanshooterOption.TARGET_HOST,
            BeanshooterOption.TARGET_PORT,
            BeanshooterOption.TARGET_BOUND_NAME,
            BeanshooterOption.TARGET_OBJID_SERVER,
            BeanshooterOption.TARGET_OBJID_CONNECTION,
            BeanshooterOption.CONN_FOLLOW,
            BeanshooterOption.CONN_SSL,
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_JOLOKIA,
            BeanshooterOption.CONN_JOLOKIA_ENDPOINT,
            BeanshooterOption.CONN_JOLOKIA_PROXY,
            BeanshooterOption.CONN_JOLOKIA_PROXY_USER,
            BeanshooterOption.CONN_JOLOKIA_PROXY_PASS,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.CONN_JNDI,
    });

    private Method method;
    private String description;
    private Option[] options;

    private Dispatcher dispatcher;

    /**
     * The constructor requires the method name that is looked up via reflection from the Dispatcher class.
     * Additionally, a description for the help menu and the available options need to be specified.
     *
     * @param methodName method to invoke when the operation was specified
     * @param description brief description of the action for the help menu
     * @param options options that should be available for the action
     */
    DiagnosticCommandOperation(String methodName, String description, Option[] options)
    {
        try
        {
            this.method = Dispatcher.class.getDeclaredMethod(methodName, new Class<?>[] {});
        }

        catch(Exception e)
        {
            ExceptionHandler.internalException(e, "Operation constructor", true);
        }

        this.description = description;
        this.options = options;
    }

    /**
     * Return the name of the operation.
     */
    public String getName()
    {
        return this.name();
    }

    /**
     * Return the description of the operation.
     */
    public String getDescription()
    {
        return this.description;
    }

    /**
     * Checks whether the current Operation contains the specified option.
     *
     * @param option option to check for
     * @return true if option is available for the current action. false otherwise.
     */
    public boolean containsOption(Option option)
    {
        for( Option o : this.options )

            if( o == option )
                return true;

        return false;
    }

    /**
     * Invoke the operation using an instance of the Dispatcher class.
     */
    public void invoke()
    {
        if( dispatcher == null )
            dispatcher = new Dispatcher();

        try {
            this.method.invoke(dispatcher);

        } catch(Exception e) {
            ExceptionHandler.internalException(e, "Operation.invoke(...)", true);
        }
    }
}
