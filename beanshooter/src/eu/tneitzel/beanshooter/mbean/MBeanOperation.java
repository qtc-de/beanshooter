package eu.tneitzel.beanshooter.mbean;

import java.lang.reflect.Method;

import eu.tneitzel.beanshooter.cli.Operation;
import eu.tneitzel.beanshooter.cli.Option;
import eu.tneitzel.beanshooter.cli.OptionHandler;
import eu.tneitzel.beanshooter.exceptions.ExceptionHandler;
import eu.tneitzel.beanshooter.operation.BeanshooterOption;
import net.sourceforge.argparse4j.inf.Subparser;
import net.sourceforge.argparse4j.inf.Subparsers;

/**
 * Enum containing the available generic MBean operations. This enum is mainly used to assign
 * options to the corresponding actions and implements the invoke function for invoking the
 * operations.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum MBeanOperation implements Operation {

    ATTR("attr", "set or get MBean attributes", new Option[] {
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
            BeanshooterOption.CONN_JOLOKIA,
            BeanshooterOption.CONN_JOLOKIA_ENDPOINT,
            BeanshooterOption.CONN_JOLOKIA_PROXY,
            BeanshooterOption.CONN_JOLOKIA_PROXY_USER,
            BeanshooterOption.CONN_JOLOKIA_PROXY_PASS,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_JNDI,
            BeanshooterOption.ATTR_ATTRIBUTE,
            BeanshooterOption.ATTR_VALUE,
            BeanshooterOption.ATTR_TYPE,
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
            BeanshooterOption.CONN_JOLOKIA,
            BeanshooterOption.CONN_JOLOKIA_ENDPOINT,
            BeanshooterOption.CONN_JOLOKIA_PROXY,
            BeanshooterOption.CONN_JOLOKIA_PROXY_USER,
            BeanshooterOption.CONN_JOLOKIA_PROXY_PASS,
            BeanshooterOption.CONN_USER,
            BeanshooterOption.CONN_PASS,
            BeanshooterOption.CONN_SASL,
            BeanshooterOption.CONN_JNDI,
            BeanshooterOption.DEPLOY_NO_STAGER,
            BeanshooterOption.DEPLOY_STAGER_URL,
            BeanshooterOption.DEPLOY_STAGER_PORT,
            BeanshooterOption.DEPLOY_STAGER_ADDR,
    }),

    EXPORT("export", "create an export of the MBean", new Option[] {
            BeanshooterOption.GLOBAL_CONFIG,
            BeanshooterOption.GLOBAL_VERBOSE,
            BeanshooterOption.GLOBAL_PLUGIN,
            BeanshooterOption.GLOBAL_NO_COLOR,
            BeanshooterOption.GLOBAL_STACK_TRACE,
            BeanshooterOption.EXPORT_DIR,
            BeanshooterOption.EXPORT_JAR,
            BeanshooterOption.EXPORT_MLET,
            BeanshooterOption.EXPORT_URL
    }),

    INFO("info", "print server information about the MBean", new Option[] {
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
            BeanshooterOption.ATTR_WRITEABLE,
            BeanshooterOption.ATTR_HARVEST,
            BeanshooterOption.ATTR_KEYWORDS,
   }),

   INVOKE("invoke", "invoke the specified method on the MBean", new Option[] {
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
            BeanshooterOption.INVOKE_METHOD_ARGS,
            BeanshooterOption.INVOKE_METHOD,
            BeanshooterOption.INVOKE_NO_WRAP,
   }),

   STATS("stats", "print local information about the MBean", new Option[] {
           BeanshooterOption.GLOBAL_CONFIG,
           BeanshooterOption.GLOBAL_VERBOSE,
           BeanshooterOption.GLOBAL_PLUGIN,
           BeanshooterOption.GLOBAL_NO_COLOR,
           BeanshooterOption.GLOBAL_STACK_TRACE,
   }),

    STATUS("status", "checks whether the MBean is registered", new Option[] {
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
    private static MBean currentBean;

    /**
     * The constructor requires the method name that is looked up via reflection from the Dispatcher class.
     * Additionally, a description for the help menu and the available options need to be specified.
     *
     * @param methodName method to invoke when the operation was specified
     * @param description brief description of the action for the help menu
     * @param options options that should be available for the action
     */
    MBeanOperation(String methodName, String description, Option[] options)
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
     * Invoke the operation using the Dispatcher class.
     */
    public void invoke()
    {
        if( currentBean == null )
            ExceptionHandler.internalError("Operation.invoke(...)", "currentBean was not set");

        if( dispatcher == null )
            this.dispatcher = new Dispatcher(currentBean);

        try
        {
            this.method.invoke(dispatcher);
        }

        catch(Exception e)
        {
            ExceptionHandler.internalException(e, "Operation.invoke(...)", true);
        }
    }

    /**
     * Set an MBean to operate on.
     *
     * @param bean MBean to operate on
     */
    public static void setMBean(MBean bean)
    {
        currentBean = bean;
    }

    /**
     * Iterates over the Operation enumeration and returns the operation that equals the specified
     * operation name. If the currentBean parameter was already set, these operations are included
     * as well.
     *
     * @param name desired Operation to return
     * @return requested Operation object or null if not found
     */
    public static Operation getByName(String name)
    {
        Operation returnItem = null;

        if( currentBean != null )

            for( Operation operation : currentBean.getOperations() )
            {
                if(operation.toString().equalsIgnoreCase(name)) {
                    returnItem = operation;
                    break;
                }
            }

        for(Operation operation : MBeanOperation.values())
        {
            if(operation.toString().equalsIgnoreCase(name)) {
                returnItem = operation;
                break;
            }
        }

        return returnItem;
    }

    /**
     * Each operation uses an individual subparser within argparse4j. These are created by this
     * function. The function creates one subparser for each member of the MBean enum and adds
     * subparsers to this subparser for each available operation (generic operations and operations
     * defined by the corresponding member of MBean).
     *
     * @param argumentParser initial parser to add the subparsers to
     */
    public static void addSubparsers(Subparsers argumentParser)
    {
        for( MBean bean : MBean.values() ) {

            Subparser parser = argumentParser.addParser(bean.getName()).help(bean.getDescription());
            Subparsers subparsers = parser.addSubparsers().help(" ").metavar(" ").dest("mbean-action");

            for( Operation operation : bean.getOperations() )
            {
                if(operation.getName().equals("ENUM"))
                    continue;

                Subparser opParser = subparsers.addParser(operation.getName().toLowerCase()).help(operation.getDescription());
                OptionHandler.addOptions(operation, opParser);
            }

            for( MBeanOperation operation : MBeanOperation.values())
            {
                if( operation.getName().equals("EXPORT") && bean.getJarName() == null )
                    continue;

                Subparser opParser = subparsers.addParser(operation.getName().toLowerCase()).help(operation.getDescription());
                OptionHandler.addOptions(operation, opParser);
            }
        }
    }
}
