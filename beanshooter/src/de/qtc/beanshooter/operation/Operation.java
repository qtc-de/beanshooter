package de.qtc.beanshooter.operation;

import java.lang.reflect.Method;

import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import net.sourceforge.argparse4j.inf.Subparser;
import net.sourceforge.argparse4j.inf.Subparsers;

/**
 * The Operation enum contains all available beanshooter operations and stores their command line names
 * as well as their help menu description. Operations are launched via reflection. During startup, each
 * enum entry fetches the associated method via reflection and invokes it then requested by the user.
 * Additionally, the Operation enum entries store their associated Options that are available for the
 * corresponding operation.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum Operation {

    BRUTE("brute", "bruteforce JMX credentials", new Option[] {}),
    DEPLOY("deploy", "deploys the specified MBean on the JMX server", new Option[] {
            Option.GLOBAL_CONFIG,
            Option.GLOBAL_VERBOSE,
            Option.GLOBAL_PLUGIN,
            Option.GLOBAL_NO_COLOR,
            Option.GLOBAL_STACK_TRACE,
            Option.TARGET_HOST,
            Option.TARGET_PORT,
            Option.TARGET_BOUND_NAME,
            Option.TARGET_OBJID_SERVER,
            Option.TARGET_OBJID_CONNECTION,
            Option.CONN_FOLLOW,
            Option.CONN_SSL,
            Option.CONN_JMXMP,
            Option.CONN_USER,
            Option.CONN_PASS,
            Option.CONN_SASL,
            Option.DEPLOY_STAGER_ONLY,
            Option.DEPLOY_NO_STAGER,
            Option.DEPLOY_STAGER_URL,
            Option.DEPLOY_STAGER_PORT,
            Option.DEPLOY_STAGER_ADDR,
            Option.DEPLOY_BEAN_CLASS,
            Option.DEPLOY_BEAN_NAME,
            Option.DEPLOY_JAR_FILE,
    }),
    DOWNLOAD("downloadFile", "download a file using a deployed tonka bean", new Option[] {}),
    ENUM("enumerate", "enumerate the JMX service for common vulnerabilities", new Option[] {}),
    EXECUTE("executeCommand", "execute a command using a deployed tonka bean", new Option[] {}),
    SERIAL("serial", "perform a deserialization attack", new Option[] {}),
    SHELL("shell", "spawn a semi interactive shell using a deployed tonka bean", new Option[] {}),
    TOMCAT("tomcat", "attempts to obtain stored credentials from tomcat based JMX", new Option[] {}),
    TONKA("invokeTonkaBean", "invoke the specified method on a deployed tonka bean", new Option[] {}),
    UNDEPLOY("undeployMBean", "undeploys the specified MBEAN from the JMX server", new Option[] {}),
    UPLOAD("uploadFile", "upload a file using a deployed tonka bean", new Option[] {});


    private Method method;
    private String description;
    private Option[] options;

    /**
     * The constructor requires the method name that is looked up via reflection from the Dispatcher class.
     * Additionally, a description for the help menu and the available options need to be specified.
     *
     * @param methodName method to invoke when the operation was specified
     * @param description brief description of the action for the help menu
     * @param options options that should be available for the action
     */
    Operation(String methodName, String description, Option[] options)
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
    public static Operation getByName(String name)
    {
        Operation returnItem = null;

        for(Operation item : Operation.values()) {
            if(item.toString().equalsIgnoreCase(name)) {
                returnItem = item;
                break;
            }
        }

        return returnItem;
    }

    /**
     * Each operation uses an individual subparser within argparse4j. These are created by this
     * function.
     *
     * @param argumentParser initial parser to add the subparsers to
     */
    public static void addSubparsers(Subparsers argumentParser)
    {
        for( Operation operation : Operation.values() ) {

            Subparser parser = argumentParser.addParser(operation.name().toLowerCase()).help(operation.description);
            Option.addOptions(operation, parser);
        }
    }

    /**
     * Invokes the method that was saved within the Operation.
     *
     * @param dispatcherObject object to invoke the method on
     */
    public void invoke(Dispatcher dispatcherObject)
    {
        try {
            this.method.invoke(dispatcherObject);

        } catch(Exception e) {
            ExceptionHandler.internalException(e, "Operation.invoke(...)", true);
        }
    }
}