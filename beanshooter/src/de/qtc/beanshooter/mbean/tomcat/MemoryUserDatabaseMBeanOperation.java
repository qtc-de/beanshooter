package de.qtc.beanshooter.mbean.tomcat;

import java.lang.reflect.Method;

import de.qtc.beanshooter.cli.Operation;
import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.operation.BeanshooterOption;

/**
 * Enum containing the available operations on the MemoryUserDatabaseMBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum MemoryUserDatabaseMBeanOperation implements Operation {

    ENUM("enumerate", "supplemental enum operation", new Option[] {}),

    DUMP("dump", "dump credentials from existing user accounts", new Option[] {
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
            MemoryUserDatabaseMBeanOption.USER_FILE,
            MemoryUserDatabaseMBeanOption.PASS_FILE,
    }),

    LIST("list", "list available users on the tomcat server", new Option[] {
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
    MemoryUserDatabaseMBeanOperation(String methodName, String description, Option[] options)
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
     * Invokes the method that was saved within the Operation.
     *
     * @param dispatcherObject object to invoke the method on
     */
    public void invoke()
    {
        if( dispatcher == null )
            dispatcher = new Dispatcher();

        try
        {
            this.method.invoke(dispatcher);
        }

        catch(Exception e)
        {
            ExceptionHandler.internalException(e, "Operation.invoke(...)", true);
        }
    }
}
