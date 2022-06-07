package de.qtc.beanshooter.mbean.flightrecorder;

import de.qtc.beanshooter.cli.ArgType;
import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.cli.OptionGroup;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentAction;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * The MLetOption enum contains available options that are dedicated to MLetOperations. The options
 * are assigned to the corresponding operations within the MLetOperation class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum FlightRecorderOption implements Option
{
    RECORDING_ID("recordingID",
                 "id of the targeted recording",
                 Arguments.store(),
                 OptionGroup.ACTION,
                 ArgType.INT
                ),

    DUMP_FILE("outfile",
                  "filename to save the dump in",
                  Arguments.store(),
                  OptionGroup.ACTION,
                  ArgType.STRING
             );

    private final String name;
    private final String description;
    private final String metavar;
    private final ArgType type;
    private final ArgumentAction argumentAction;
    private OptionGroup optionGroup = null;

    private Object value = null;


    /**
     * Initialize the MLetOption with the required parameters.
     *
     * @param name option name on the command line
     * @param description option description within the help menu
     * @param argumentAction argument action to use (flag or option)
     * @param optionGroup OptionGroup that the argument belongs to
     * @param type ArgType to expect from the argument
     */
    FlightRecorderOption(String name, String description, ArgumentAction argumentAction, OptionGroup optionGroup, ArgType type)
    {
        this(name, description, argumentAction, optionGroup, type, null);
    }

    /**
     * Initialize the MLetOption with the required parameters.
     *
     * @param name option name on the command line
     * @param description option description within the help menu
     * @param argumentAction argument action to use (flag or option)
     * @param optionGroup OptionGroup that the argument belongs to
     * @param type ArgType to expect from the argument
     * @param metavar meta variable to display in the help menu
     */
    FlightRecorderOption(String name, String description, ArgumentAction argumentAction, OptionGroup optionGroup, ArgType type, String metavar)
    {
        this.name = name;
        this.description = description;
        this.argumentAction = argumentAction;

        this.type = type;
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
     * Return the option name.
     */
    public String getName()
    {
        return name;
    }

    /**
     * Return the option description.
     */
    public String description()
    {
        return description;
    }

    /**
     * Return the expected ArgType.
     */
    public ArgType getArgType()
    {
        return type;
    }

    /**
     * Return the OptionGroup the option belongs to.
     */
    public OptionGroup optionGroup()
    {
        return optionGroup;
    }

    /**
     * Return the option's ArgumentAction (flag or option).
     */
    public ArgumentAction argumentAction()
    {
        return argumentAction;
    }

    /**
     * return the options meta variable.
     */
    public String metavar()
    {
        return metavar;
    }
}
