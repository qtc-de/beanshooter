package eu.tneitzel.beanshooter.cli;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;
import java.util.Properties;

import eu.tneitzel.beanshooter.exceptions.ExceptionHandler;
import eu.tneitzel.beanshooter.io.Logger;
import eu.tneitzel.beanshooter.mbean.MBean;
import eu.tneitzel.beanshooter.mbean.MBeanOperation;
import eu.tneitzel.beanshooter.operation.BeanshooterOperation;
import eu.tneitzel.beanshooter.operation.BeanshooterOption;
import eu.tneitzel.beanshooter.plugin.PluginSystem;
import eu.tneitzel.beanshooter.utils.Utils;
import net.sourceforge.argparse4j.ArgumentParsers;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.ArgumentParserException;
import net.sourceforge.argparse4j.inf.Namespace;
import net.sourceforge.argparse4j.inf.Subparsers;

/**
 * The ArgumentHandler is a wrapper around the ArgumentParser of argparse4j. It handles
 * some special cases and takes care of initializing some stuff like e.g. the plugin system.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ArgumentHandler
{
    private Namespace args;
    private ArgumentParser parser;
    private Properties config;
    private Operation action = null;

    private static ArgumentHandler instance = null;
    private static final String defaultConfiguration = "/config.properties";

    /**
     * Creates an ArgumentParser and adds one subparser for each supported operation. After
     * creating the parsers, it parses the current command line and starts the initialization
     * process. The initialized ArgumentHandler object is set as a static class attribute that
     * can be accessed by other classes to obtain the instance.
     *
     * @param argv the specified command line arguments
     */
    public ArgumentHandler(String[] argv)
    {
        parser = ArgumentParsers.newFor("beanshooter").build();
        parser.description("beanshooter v" + ArgumentHandler.class.getPackage().getImplementationVersion() + " - a JMX enumeration and attacking tool");

        Subparsers subparsers = parser.addSubparsers().help(" ").metavar(" ").dest("action");
        BeanshooterOperation.addSubparsers(subparsers);
        MBeanOperation.addSubparsers(subparsers);

        try {
            args = parser.parseArgs(argv);

        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(1);
        }

        initialize();

        if( ArgumentHandler.instance == null )
            ArgumentHandler.instance = this;
    }

    /**
     * Load the configuration file and sets default options for options that were not specified explicitly.
     * Processes some special command line switches and initializes the plugin system.
     */
    private void initialize()
    {
        config = loadConfig(args.get(BeanshooterOption.GLOBAL_CONFIG.name()));
        OptionHandler.prepareOptions(args, config);

        if( BeanshooterOption.GLOBAL_NO_COLOR.getBool() )
            Logger.disableColor();

        PluginSystem.init(BeanshooterOption.GLOBAL_PLUGIN.getValue());
    }

    /**
     * Loads the beanshooter configuration file from the specified destination. The default configuration
     * is always loaded. If the filename parameter is not null, an additional user specified config is loaded, that
     * may overwrites some configurations. The default configuration file should store default values for all
     * beanshooter options.
     *
     * @param filename file system path to load the configuration file from
     */
    private Properties loadConfig(String filename)
    {
        Properties config = new Properties();

        try {
            InputStream configStream = null;

            configStream = ArgumentParser.class.getResourceAsStream(defaultConfiguration);
            config.load(configStream);
            configStream.close();

            if( filename != null ) {
                configStream = new FileInputStream(filename);
                config.load(configStream);
                configStream.close();
            }

        } catch( IOException e ) {
            ExceptionHandler.unexpectedException(e, "loading", ".properties file", true);
        }

        return config;
    }

    /**
     * Obtain an item from the beanshooter configuration file.
     *
     * @param property the property to lookup
     * @return configured value for this property
     */
    public String getFromConfig(String property)
    {
        return (String) config.get(property);
    }

    /**
     * Returns the user specified beanshooter action.
     *
     * @return Operation requested by the client
     */
    public Operation getAction()
    {
        String actionArg = args.getString("action");
        this.action = BeanshooterOperation.getByName(actionArg);

        if( action == null ) {

            MBean selectedBean = MBean.getMBean(actionArg);

            if( selectedBean == null )
                ExceptionHandler.internalError("ArgumentHandler.getAction", "Unable to find MBean with name: " + selectedBean);

            MBeanOperation.setMBean(selectedBean);
            String mBeanAction = args.getString("mbean-action");

            this.action = MBeanOperation.getByName(mBeanAction);
        }

        if( action == null )
            ExceptionHandler.internalError("ArgumentHandler.getAction", "The specified action is not avaialble");

        return action;
    }

    /**
     * Parses the user specified gadget arguments to request a corresponding gadget from the PayloadProvider.
     * The corresponding gadget object is returned.
     *
     * @return gadget object build from the user specified arguments
     */
    public Object getGadget()
    {
        String gadget = (String) require(BeanshooterOption.SERIAL_GADGET_NAME);
        String command = require(BeanshooterOption.SERIAL_GADGET_CMD);

        return PluginSystem.getPayloadObject(this.getAction(), gadget, command);
    }

    /**
     * Other classes can use this function to obtain the current instance of the ArgumentHandler
     * class.
     *
     * @return currently used instance of ArgumentHandler
     */
    public static ArgumentHandler getInstance()
    {
        return ArgumentHandler.instance;
    }

    /**
     * Parses the user specified SASL mechanism and returns it in form of a member of the
     * SASLMechanism enum. null is returned if no SASL mechanism was specified.
     *
     * @return user specified SASLMechanism or null
     */
    public static SASLMechanism getSASLMechanism()
    {
        if( BeanshooterOption.CONN_SASL.isNull() )
            return null;

        String mechanism = BeanshooterOption.CONN_SASL.getValue();
        return SASLMechanism.valueOf(mechanism.toUpperCase());
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
                return (T)option.getValue();

            } catch( ClassCastException e ) {
                ExceptionHandler.internalError("RMGOption.require", "Caught class cast exception.");
            }
        }

        Logger.resetIndent();
        Logger.eprintlnMixedYellow("Error: The specified aciton requires the", option.getName(), "option.");
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

        for (Option option : options)
        {
            if( option.notNull() )
                return option.getValue();

            helpString.append(option.getName());
            helpString.append(", ");
        }

        helpString.setLength(helpString.length() - 2);

        Logger.resetIndent();
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
        boolean failed = false;
        StringBuilder helpString = new StringBuilder();

        for( Option option : options )
        {
            if( option.isNull() )
                failed = true;

            helpString.append(option.getName());
            helpString.append(", ");
        }

        helpString.setLength(helpString.length() - 2);

        if( failed )
        {
            Logger.resetIndent();
            Logger.eprintlnMixedYellow("Error: The specified aciton requires the", helpString.toString(), "options.");
            Utils.exit();
        }
    }

    /**
     * Authentication to JMX endpoints is usually handled using a map that contains the authentication
     * parameters. This function is used to prepare such a map by using the Options specified on the command
     * line.
     *
     * @return environment that should be used during the newClient call
     */
    public static Map<String,Object> getEnv()
    {
        return PluginSystem.getEnv(BeanshooterOption.CONN_USER.getValue(), BeanshooterOption.CONN_PASS.getValue());
    }
}
