package de.qtc.beanshooter.cli;

import java.util.EnumSet;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.management.remote.JMXConnector;
import javax.rmi.ssl.SslRMIClientSocketFactory;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.Operation;
import de.qtc.beanshooter.utils.Utils;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.Argument;
import net.sourceforge.argparse4j.inf.ArgumentAction;
import net.sourceforge.argparse4j.inf.ArgumentGroup;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * All available beanshooter options are defined in the Option enum. The enum stores the option
 * names, their description, the information whether they are boolean or store values and an optional
 * meta variable. Additionally, each Option is assigned to an OptionGroup. This is used for grouping
 * related arguments in the help menu of the programm.
 *
 * Options are not assigned to operations here. This is done within the Operation class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum Option {

    GLOBAL_CONFIG("--config", "path to a configuration file", Arguments.store(), OptionGroup.GENERAL, "config-file"),
    GLOBAL_VERBOSE("--verbose", "enable verbose output", Arguments.storeTrue(), OptionGroup.GENERAL),
    GLOBAL_PLUGIN("--plugin", "file system path to a beanshooter plugin", Arguments.store(), OptionGroup.GENERAL, "plugin-file"),
    GLOBAL_NO_COLOR("--no-color", "disable colored output", Arguments.storeTrue(), OptionGroup.GENERAL),
    GLOBAL_STACK_TRACE("--stack-trace", "display stack traces for caught exceptions", Arguments.storeTrue(), OptionGroup.GENERAL),

    TARGET_HOST("host", "target host", Arguments.store(), OptionGroup.NONE, "host"),
    TARGET_PORT("port", "target port", Arguments.store(), OptionGroup.NONE, "port"),
    TARGET_BOUND_NAME("--bound-name", "target bound name within an RMI registry", Arguments.store(), OptionGroup.TARGET, "name"),
    TARGET_OBJID_SERVER("--objid-server", "target ObjID for an RMIServer remote object", Arguments.store(), OptionGroup.TARGET, "objid"),
    TARGET_OBJID_CONNECTION("--objid-connection", "target ObjID for an RMIConnection remote object", Arguments.store(), OptionGroup.TARGET, "objid"),

    CONN_FOLLOW("--follow", "follow redirects to different servers", Arguments.storeTrue(), OptionGroup.CONNECTION),
    CONN_SSL("--ssl", "use SSL for connections", Arguments.storeTrue(), OptionGroup.CONNECTION),
    CONN_JMXMP("--jmxmp", "use JMXMP for JMX communication", Arguments.storeTrue(), OptionGroup.CONNECTION),
    CONN_USER("--username", "username to use for JMX authentication", Arguments.store(), OptionGroup.CONNECTION, "user"),
    CONN_PASS("--password", "password to use for JMX authentication", Arguments.store(), OptionGroup.CONNECTION, "pass"),
    CONN_SASL("--sasl", "use SASL auth mechanism for JMXMP", Arguments.storeTrue(), OptionGroup.CONNECTION),

    DEPLOY_STAGER_ONLY("--stager-only", "only launch the stager HTTP server", Arguments.storeTrue(), OptionGroup.ACTION),
    DEPLOY_NO_STAGER("--no-stager", "do not launch the stager HTTP server", Arguments.storeTrue(), OptionGroup.ACTION),
    DEPLOY_STAGER_URL("--stager-url", "url of the stager server", Arguments.store(), OptionGroup.ACTION, "URL"),
    DEPLOY_STAGER_PORT("--stager-port", "TCP port to start the stager on", Arguments.store(), OptionGroup.ACTION, "port"),
    DEPLOY_STAGER_ADDR("--stager-host", "IP address to start the stager on", Arguments.store(), OptionGroup.ACTION, "addr"),
    DEPLOY_BEAN_CLASS("--classname", "classname of the MBean to deploy", Arguments.store(), OptionGroup.BEAN, "name"),
    DEPLOY_BEAN_NAME("--object-name", "object name of the MBean to deploy", Arguments.store(), OptionGroup.BEAN, "name"),
    DEPLOY_JAR_FILE("--jar", "jar archive to deploy", Arguments.store(), OptionGroup.BEAN, "path"),

    BRUTE_THREADS("--threads", "maximum number of threads (default: 5)", Arguments.store(), OptionGroup.ACTION, "threads"),
    YSO("--yso", "location of ysoserial.jar for deserialization attacks", Arguments.store(), OptionGroup.ACTION, "yso-path");

    public final String name;
    public final String description;
    public final String metavar;
    public final ArgumentAction argumentAction;
    public OptionGroup optionGroup = null;

    public Object value = null;

    private final static EnumSet<Option> intOptions = EnumSet.of(TARGET_PORT, DEPLOY_STAGER_PORT, BRUTE_THREADS);
    private final static EnumSet<Option> booleanOptions = EnumSet.of(GLOBAL_CONFIG);

    /**
     * Initializes an enum field with the corresponding Option name, the Option description the argument action,
     * which decides whether the option is boolean or expects a value and an RMGOptionGroup, that is used to
     * group options within command line help.
     *
     * @param name Name of the option. As used on the command line
     * @param description Description that is shown within the help menu
     * @param argumentAction argparse4j ArgumentAction for this option
     * @param optionGroup Logical group to display the argument in when printing the help menu
     */
    Option(String name, String description, ArgumentAction argumentAction, OptionGroup optionGroup)
    {
        this(name, description, argumentAction, optionGroup, null);
    }

    /**
     * Initializes an enum field with the corresponding Option name, the Option description the argument action,
     * which decides whether the option is boolean or expects a value, an RMGOptionGroup, that is used to
     * group options within command line help and the name metavar of the option value, if required.
     *
     * @param name Name of the option. As used on the command line
     * @param description Description that is shown within the help menu
     * @param argumentAction argparse4j ArgumentAction for this option
     * @param optionGroup Logical group to display the argument in when printing the help menu
     * @param metavar Meta name for the expected option value
     */
    Option(String name, String description, ArgumentAction argumentAction, OptionGroup optionGroup, String metavar)
    {
        this.name = name;
        this.description = description;
        this.argumentAction = argumentAction;

        this.metavar = metavar;
        this.optionGroup = optionGroup;
    }

    /**
     * Returns true if the value is null.
     *
     * @return true or false
     */
    public boolean isNull()
    {
        if( this.value == null)
            return true;

        return false;
    }

    /**
     * Returns true if a value is set.
     *
     * @return true or false
     */
    public boolean notNull()
    {
        if( this.value == null)
            return false;

        return true;
    }

    /**
     * Returns the option value as boolean.
     *
     * @return option value as boolean
     */
    public boolean getBool()
    {
        if( this.value == null)
            return false;

        return (boolean)this.value;
    }

    /**
     * Returns the value stored within the option.
     *
     * @return value stored within the option
     */
    @SuppressWarnings("unchecked")
    public <T> T getValue()
    {
        try {
            return (T)value;

        } catch( ClassCastException e ) {
            ExceptionHandler.internalError("RMGOption.getValue", "ClassCastException was caught.");
        }

        return null;
    }

    /**
     * Sets the option to the specified value.
     *
     * @param value Object value to set for this option
     */
    public void setValue(Object value)
    {
        this.value = value;
    }

    /**
     * Sets the option to the specified value. If the value is null, use the specified default.
     *
     * @param value Object value to set for this option
     * @param def Default value to set for this option
     */
    public void setValue(Object value, Object def)
    {
        if( value != null )
            this.value = value;

        else
            this.value = def;
    }

    /**
     * Attempts to set an option value obtained from an argparse4j Namespace object.
     * If the corresponding option was not specified, use the default value.
     *
     * @param value
     */
    public void setValue(Namespace args, Object def)
    {
        this.value = args.get(this.name.replaceFirst("--", "").replace("-", "_"));
        this.setValue(value, def);
    }


    /**
     * Prepare the Option enum by using an argparse4j Namespace object and the global
     * beanshooter configuration. This function initializes all options within
     * the enum and uses either the value that was specified on the command line or the
     * value obtained from the configuration file.
     *
     * @param args argparse4j Namespace for the current command line
     * @param config global beanshooter configuration
     */
    public static void prepareOptions(Namespace args, Properties config)
    {
        for(Option option : Option.values() ) {

            Object defaultValue = config.getProperty(option.name().toLowerCase());

            try {

                if( defaultValue != null && !((String) defaultValue).isEmpty() ) {

                    if( intOptions.contains(option) )
                        defaultValue = Integer.valueOf((String) defaultValue);

                    else if( booleanOptions.contains(option) )
                        defaultValue = Boolean.valueOf((String) defaultValue);

                } else if( defaultValue != null && ((String) defaultValue).isEmpty() ) {
                    defaultValue = null;
                }

            } catch( Exception e ) {
                Logger.eprintlnMixedYellow("RMGOption", option.name, "obtained an invalid argument.");
                ExceptionHandler.stackTrace(e);
                Utils.exit();
            }

            option.setValue(args, defaultValue);
        }
    }

    /**
     * Adds options from the Option enum to an argument parser. The options that are added depend
     * on the currently selected action, which is expected as one of the arguments. Arguments that
     * belong to an OptionGroup are added to the corresponding group and the group is added to the
     * parser.
     *
     * @param operation beanshooter operation specified on the command line
     * @param argParser argparse4j ArgumentParser object for the current command line
     */
    public static void addOptions(Operation operation, ArgumentParser argParser)
    {
        Argument arg;
        OptionGroup group;
        ArgumentGroup arggroup;

        for( Option option : Option.values() ) {

            if( !operation.containsOption(option) )
                continue;

            group = option.optionGroup;

            if( group == OptionGroup.NONE || group == OptionGroup.ACTION )
                arg = argParser.addArgument(option.name).help(option.description).action(option.argumentAction);

            else {
                arggroup = group.addArgumentGroup(argParser, operation);
                arg = arggroup.addArgument(option.name).help(option.description).action(option.argumentAction);
            }

            addModifiers(option, arg);
        }
    }

    /**
     * Certain options only allow a specific set of arguments, have metavariables, expect multiple variables or
     * are expected to be of a specific type. This function adds these requirements to the options. It is not
     * very elegant to assign these attributes in a static function, but only a few arguments require such
     * attributes and initializing them in the enum constructor would make the whole class less readable.
     *
     * @param option Option that is checked for special attribute requirements
     * @param arg Argument to apply special attributes to
     */
    public static void addModifiers(Option option, Argument arg)
    {
        if( option.metavar != null )
            arg.metavar(option.metavar);

        if( intOptions.contains(option) )
            arg.type(Integer.class);
    }

    /**
     * The require function allows other parts of the source code to require an option value.
     * If the corresponding option was not set, an error message is printed and the current execution
     * ends. This should be called first by functions that require an specific argument.
     *
     * @param option Option that is required
     * @return the currently set option value
     */
    @SuppressWarnings("unchecked")
    public static <T> T require(Option option)
    {
        if( option.notNull() ) {

            try {
                return (T)option.value;

            } catch( ClassCastException e ) {
                ExceptionHandler.internalError("RMGOption.require", "Caught class cast exception.");
            }
        }

        Logger.eprintlnMixedYellow("Error: The specified aciton requires the", option.name, "option.");
        Utils.exit();

        return null;
    }

    /**
     * Allows other parts of the source code to check whether one of the requested Options was
     * specified on the command line. If none of the requested Options was found, print an error
     * and exit. This should be called first by functions that requires one of a set of Options.
     *
     * @param options Options to check for
     * @return the value of the first option that was found.
     */
    public static Object requireOneOf(Option... options)
    {
        StringBuilder helpString = new StringBuilder();

        for( Option option : options ) {

            if( option.notNull() )
                return option.value;

            helpString.append(option.name);
            helpString.append(", ");
        }

         helpString.setLength(helpString.length() - 2);

        Logger.eprintlnMixedYellow("Error: The specified aciton requires one of the", helpString.toString(), "options.");
        Utils.exit();

        return null;
    }

    /**
     * Allows other parts of the source code to check whether all of the requested Options were
     * specified on the command line. If not all of the requested Options was found, print an error
     * and exit. This should be called first by functions that requires a set of Options.
     *
     * @param options Options to check for
     */
    public static void requireAllOf(Option... options)
    {
        for( Option option : options ) {

            if( !option.notNull() ) {
                Logger.eprintlnMixedYellow("Error: The specified aciton requires the", option.name, "option.");
                Utils.exit();
            }
        }
    }

    /**
     * Authentication to JMX endpoints is usually handled using a map that contains the authentication
     * parameters. This function is used to prepare such a map by using the Options specified on the command
     * line.
     *
     * @return
     */
    public static Map<String,Object> getEnv()
    {
        HashMap<String,Object> env = new HashMap<String,Object>();

        if(Option.CONN_SSL.getBool())
            env.put("com.sun.jndi.rmi.factory.socket", new SslRMIClientSocketFactory());

        if(Option.CONN_USER.notNull() && Option.CONN_PASS.notNull())
            env.put(JMXConnector.CREDENTIALS, new String[] {Option.CONN_USER.getValue(), Option.CONN_PASS.getValue()});

        return env;
    }
}
