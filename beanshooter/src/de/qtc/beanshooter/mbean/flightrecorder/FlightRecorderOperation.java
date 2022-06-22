package de.qtc.beanshooter.mbean.flightrecorder;

import java.lang.reflect.Method;

import de.qtc.beanshooter.cli.Operation;
import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.operation.BeanshooterOption;

/**
 * The FlightRecorderOperation enum contains operations that are available on a deployed FlightRecorder MBean.
 * Furthermore, it defines the options that are available for the corresponding operations.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum FlightRecorderOperation implements Operation
{
    NEW("newRecording", "create a new recording", new Option[] {
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
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
    }),

    START("startRecording", "start a recording", new Option[] {
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
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            FlightRecorderOption.RECORDING_ID,
    }),

    STOP("stopRecording", "stop a recording", new Option[] {
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
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            FlightRecorderOption.RECORDING_ID,
    }),

    READ("readRecording", "read a recording and store it to a local file", new Option[] {
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
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            FlightRecorderOption.RECORDING_ID,
            FlightRecorderOption.DUMP_FILE,
    }),

    DUMP("dumpRecording", "dump a recording to a file on the server", new Option[] {
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
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            FlightRecorderOption.RECORDING_ID,
            FlightRecorderOption.DUMP_FILE,
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
    FlightRecorderOperation(String methodName, String description, Option[] options)
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
