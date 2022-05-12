package de.qtc.beanshooter.operation;

import java.lang.reflect.Method;

import de.qtc.beanshooter.cli.Operation;
import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.cli.OptionHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.mbean.mlet.MLetOption;
import net.sourceforge.argparse4j.inf.Subparser;
import net.sourceforge.argparse4j.inf.Subparsers;

/**
 * The BeanshooterOperation enum contains the top-level beanshooter operations that can be used on
 * the command line. The operations contained in this enum are supplemented by operations added by
 * the member of the MBean enum defined in the de.qtc.beanshooter.mbean package.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum BeanshooterOperation implements Operation {

    BRUTE("brute", "bruteforce JMX credentials", new Option[] {
            BeanshooterOption.GLOBAL_CONFIG,
            BeanshooterOption.GLOBAL_VERBOSE,
            BeanshooterOption.GLOBAL_PLUGIN,
            BeanshooterOption.GLOBAL_NO_COLOR,
            BeanshooterOption.GLOBAL_STACK_TRACE,
            BeanshooterOption.TARGET_HOST,
            BeanshooterOption.TARGET_PORT,
            BeanshooterOption.TARGET_BOUND_NAME,
            BeanshooterOption.TARGET_OBJID_SERVER,
            BeanshooterOption.CONN_FOLLOW,
            BeanshooterOption.CONN_SSL,
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.BRUTE_USER_FILE,
            BeanshooterOption.BRUTE_PW_FILE,
            BeanshooterOption.BRUTE_USER,
            BeanshooterOption.BRUTE_PASSWORD,
            BeanshooterOption.BRUTE_THREADS,
            BeanshooterOption.BRUTE_FIRST,
            BeanshooterOption.NO_PROGRESS,
    }),

    INVOKE("invoke", "invoke the specified method on the specified MBean", new Option[] {
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
             BeanshooterOption.INVOKE_OBJ_NAME,
             BeanshooterOption.INVOKE_METHOD_ARGS,
             BeanshooterOption.INVOKE_LITERAL,
             BeanshooterOption.INVOKE_METHOD,
             BeanshooterOption.INVOKE_NO_WRAP,
    }),

    DEPLOY("deploy", "deploys the specified MBean on the JMX server", new Option[] {
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
            BeanshooterOption.DEPLOY_STAGER_ONLY,
            BeanshooterOption.DEPLOY_NO_STAGER,
            BeanshooterOption.DEPLOY_STAGER_URL,
            BeanshooterOption.DEPLOY_STAGER_PORT,
            BeanshooterOption.DEPLOY_STAGER_ADDR,
            BeanshooterOption.DEPLOY_BEAN_CLASS,
            BeanshooterOption.DEPLOY_BEAN_NAME,
            BeanshooterOption.DEPLOY_JAR_FILE,
    }),

    ENUM("enumerate", "enumerate the JMX service for common vulnerabilities", new Option[] {
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
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_FOLLOW,
            BeanshooterOption.CONN_SSL,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
    }),

    LIST("list", "list available MBEans on the remote MBean server", new Option[] {
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
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_FOLLOW,
            BeanshooterOption.CONN_SSL,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.LIST_FILTER_CLASS,
            BeanshooterOption.LIST_FILTER_OBJ,
    }),


    SERIAL("serial", "perform a deserialization attack", new Option[] {
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
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_JMXMP,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.SERIAL_GADGET_NAME,
            BeanshooterOption.SERIAL_GADGET_CMD,
            BeanshooterOption.YSO,
            BeanshooterOption.SERIAL_PREAUTH,
    }),

    STAGER("stager", "start a stager server to deliver MBeans", new Option[] {
            BeanshooterOption.GLOBAL_CONFIG,
            BeanshooterOption.GLOBAL_VERBOSE,
            BeanshooterOption.GLOBAL_PLUGIN,
            BeanshooterOption.GLOBAL_NO_COLOR,
            BeanshooterOption.GLOBAL_STACK_TRACE,
            MLetOption.LOAD_BEAN,
            BeanshooterOption.STAGER_PORT,
            BeanshooterOption.STAGER_HOST,
            BeanshooterOption.DEPLOY_STAGER_URL,
            MLetOption.LOAD_CLASS_NAME,
            MLetOption.LOAD_OBJECT_NAME,
            MLetOption.LOAD_JAR_FILE,
    }),

    UNDEPLOY("undeploy", "undeploys the specified MBEAN from the JMX server", new Option[] {
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
            BeanshooterOption.UNDEPLOY_BEAN_NAME,
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
    BeanshooterOperation(String methodName, String description, Option[] options)
    {
        try {
            this.method = Dispatcher.class.getDeclaredMethod(methodName, new Class<?>[] {});

        } catch(Exception e) {
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
     * Iterates over the Operation enumeration and returns the operation that equals the specified
     * operation name.
     *
     * @param name desired Operation to return
     * @return requested Operation object or null if not found
     */
    public static BeanshooterOperation getByName(String name)
    {
        BeanshooterOperation returnItem = null;

        for(BeanshooterOperation item : BeanshooterOperation.values())
        {
            if(item.toString().equalsIgnoreCase(name))
            {
                returnItem = item;
                break;
            }
        }

        return returnItem;
    }

    /**
     * Each operation uses an individual subparser within argparse4j. These are created by this
     * function. Apart from the actual beanshooter operations, there are operations implemented
     * by MBeans that beanshooter can deploy. These subparsers are added by the MBeanOperation
     * class in a different step.
     *
     * @param argumentParser initial parser to add the subparsers to
     */
    public static void addSubparsers(Subparsers argumentParser)
    {
        for( BeanshooterOperation operation : BeanshooterOperation.values() )
        {
            Subparser parser = argumentParser.addParser(operation.name().toLowerCase()).help(operation.description);
            OptionHandler.addOptions(operation, parser);
        }
    }

    /**
     * Invokes the operation using an instance of the Dispatcher class.
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
