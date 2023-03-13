package de.qtc.beanshooter.cli;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.mbean.mlet.MLetOption;
import de.qtc.beanshooter.mbean.tomcat.MemoryUserDatabaseMBeanOption;
import de.qtc.beanshooter.mbean.tonkabean.TonkaBeanOption;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.utils.Utils;
import net.sourceforge.argparse4j.inf.Argument;
import net.sourceforge.argparse4j.inf.ArgumentGroup;
import net.sourceforge.argparse4j.inf.ArgumentParser;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * The OptionHandler class (not to be confused with the ArgumentHandler class) is a helper class
 * that is used to initialize the beanshooter and MBean options. Options are either defined
 * within the de.qtc.beanshooter.operation.BeanshooterOption class or within classes specified
 * in the MBeam enum. This class uses a static block to obtain all these options and implements
 * functions to initialize them.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class OptionHandler {

    private static Option[] options;

    static {
        List<Option> opts = new ArrayList<Option>();
        opts.addAll(Arrays.asList(BeanshooterOption.values()));

        for( MBean bean : MBean.values() )
            opts.addAll(Arrays.asList(bean.getOptions()));

        options = opts.toArray(new Option[0]);
    }

    /**
     * This function initializes all statically obtained options and uses either the value
     * that was specified on the command line or the value obtained from the configuration file.
     *
     * @param args argparse4j Namespace for the current command line
     * @param config global beanshooter configuration
     */
    public static void prepareOptions(Namespace args, Properties config)
    {
        for(Option option : options) {

            Object defaultValue = config.getProperty(option.name().toLowerCase());

            try {

                if( defaultValue != null && !((String) defaultValue).isEmpty() ) {

                    if( option.getArgType() == ArgType.INT )
                        defaultValue = Integer.valueOf((String) defaultValue);

                    else if( option.getArgType() == ArgType.BOOL )
                        defaultValue = Boolean.valueOf((String) defaultValue);

                } else if( defaultValue != null && ((String) defaultValue).isEmpty() ) {
                    defaultValue = null;
                }

            } catch( Exception e ) {
                Logger.eprintlnMixedYellow("RMGOption", option.getName(), "obtained an invalid argument.");
                ExceptionHandler.stackTrace(e);
                Utils.exit();
            }

            option.setValue(args, defaultValue);
        }
    }

    /**
     * Adds options from the options array to an argument parser. The options that are added depend
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

        for( Option option : options ) {

            if( !operation.containsOption(option) )
                continue;

            group = option.optionGroup();

            if( group == OptionGroup.NONE || group == OptionGroup.ACTION )
                arg = argParser.addArgument(option.getName()).help(option.description()).action(option.argumentAction());

            else {
                arggroup = group.addArgumentGroup(argParser, operation);
                arg = arggroup.addArgument(option.getName()).help(option.description()).action(option.argumentAction());
            }

            addModifiers(option, arg);
        }
    }

    /**
     * Certain options only allow a specific set of arguments, have metavariables, expect multiple variables or
     * are expected to be of a specific type. This function adds these requirements to the options. It is not
     * very elegant to assign these attributes in a static function, but only a few arguments require such
     * attributes and initializing them in the enum constructors would make the whole classes less readable.
     *
     * @param option Option that is checked for special attribute requirements
     * @param arg Argument to apply special attributes to
     */
    public static void addModifiers(Option option, Argument arg)
    {
        if( option.metavar() != null )
            arg.metavar(option.metavar());

        if( option.getArgType() == ArgType.INT )
            arg.type(Integer.class);

        if( option == BeanshooterOption.CONN_SASL )
            arg.choices(SASLMechanism.getMechanisms());

        if (option == BeanshooterOption.INVOKE_METHOD_ARGS)
            arg.nargs("*");

        if (option == TonkaBeanOption.EXEC_ARRAY)
            arg.nargs("+");

        if (option == TonkaBeanOption.DOWNLOAD_DEST)
            arg.nargs("?");

        if (option == TonkaBeanOption.UPLOAD_DEST)
            arg.nargs("?");

        if (option == BeanshooterOption.ATTR_VALUE)
            arg.nargs("?");

        if (option == BeanshooterOption.MODEL_RESOURCE)
            arg.nargs("?");

        if (option == BeanshooterOption.OBJ_NAME)
            arg.nargs("?");

        if (option == BeanshooterOption.ATTR_VALUE)
            arg.nargs("?");

        if (option == MemoryUserDatabaseMBeanOption.PASS_FILE)
            arg.nargs("?");

        if( option == MLetOption.LOAD_BEAN )
        {
            List<String> mBeanNames = MBean.getLoadableBeanNames();
            mBeanNames.add("custom");
            arg.choices(mBeanNames);
        }
    }
}
