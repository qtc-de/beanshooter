package de.qtc.beanshooter.cli;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.Operation;
import de.qtc.beanshooter.plugin.PluginSystem;
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
public class ArgumentHandler {

    private Namespace args;
    private ArgumentParser parser;
    private Properties config;
    private Operation action = null;

    private  String defaultConfiguration = "/config.properties";

    /**
     * Creates an ArgumentParser and adds one subparser for each supported operation. After
     * creating the parsers, it parses the current command line and starts the initialization
     * process.
     *
     * @param argv the specified command line arguments
     */
    public ArgumentHandler(String[] argv)
    {
        parser = ArgumentParsers.newFor("beanshooter").build();
        parser.description("beanshooter v" + ArgumentHandler.class.getPackage().getImplementationVersion() + " - a JMX Vulnerability Scanner");

        Subparsers subparsers = parser.addSubparsers().help(" ").metavar("action").dest("action");
        Operation.addSubparsers(subparsers);

        try {
            args = parser.parseArgs(argv);

        } catch (ArgumentParserException e) {
            parser.handleError(e);
            System.exit(1);
        }

        initialize();
    }

    /**
     * Load the configuration file and sets default options for options that were not specified explicitly.
     * Processes some special command line switches and initializes the plugin system.
     */
    private void initialize()
    {
        config = loadConfig(args.get(Option.GLOBAL_CONFIG.name));
        Option.prepareOptions(args, config);

        if( Option.GLOBAL_NO_COLOR.getBool() )
            Logger.disableColor();

        PluginSystem.init(Option.GLOBAL_PLUGIN.getValue());
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
     * Returns the user specified beanshooter action.
     *
     * @return Operation requested by the client
     */
    public Operation getAction()
    {
        this.action = Operation.getByName(args.getString("action"));

        if( action == null )
            ExceptionHandler.internalError("ArgumentHandler.getAction", "Invalid action was specified");

        return action;
    }
}
