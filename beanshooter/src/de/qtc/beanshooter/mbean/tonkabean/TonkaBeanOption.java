package de.qtc.beanshooter.mbean.tonkabean;

import de.qtc.beanshooter.cli.ArgType;
import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.cli.OptionGroup;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentAction;
import net.sourceforge.argparse4j.inf.Namespace;

public enum TonkaBeanOption implements Option
{
    SHELL_CMD("--shell",
              "the shell command to use for execution",
              Arguments.store(),
              OptionGroup.ACTION,
              ArgType.STRING,
              "shell"
              ),

    EXEC_BACK("--background",
              "execute the command in the background",
              Arguments.storeTrue(),
              OptionGroup.ACTION,
              ArgType.BOOL
              ),

    EXEC_CMD("cmd",
             "command to execute",
             Arguments.store(),
             OptionGroup.ACTION,
             ArgType.STRING
             ),

    EXEC_ARRAY("cmd",
               "command to execute",
               Arguments.store(),
               OptionGroup.ACTION,
               ArgType.ARRAY
               ),

    EXEC_CWD("--cwd",
             "working directory to execute the command in",
             Arguments.store(),
             OptionGroup.ACTION,
             ArgType.STRING,
             "cwd"
             ),

    EXEC_ENV("--env",
             "environment variables to use with the command",
             Arguments.store(),
             OptionGroup.ACTION,
             ArgType.STRING,
             "env"
             ),

    EXEC_HEX("--hex",
             "return the command output as hexstring",
             Arguments.storeTrue(),
             OptionGroup.ACTION,
             ArgType.BOOL),

    EXEC_FILE("--output-file",
              "write the command output into a file",
              Arguments.store(),
              OptionGroup.ACTION,
              ArgType.STRING,
              "file"
              ),

    EXEC_RAW("--raw",
             "return the raw output of the command without diagnostic messages",
             Arguments.storeTrue(),
             OptionGroup.ACTION,
             ArgType.BOOL
             ),

    UPLOAD_SOURCE("local",
                  "local file to upload onto the server",
                  Arguments.store(),
                  OptionGroup.ACTION,
                  ArgType.STRING
                  ),

    UPLOAD_DEST("remote",
                "remote path to upload the file to",
                Arguments.store(),
                OptionGroup.ACTION,
                ArgType.STRING
                ),

    DOWNLOAD_SOURCE("remote",
                    "remote path to download the file from",
                    Arguments.store(),
                    OptionGroup.ACTION,
                    ArgType.STRING
                   ),

    DOWNLOAD_DEST("local",
                  "local path to save the downloaded file to",
                  Arguments.store(),
                  OptionGroup.ACTION,
                  ArgType.STRING
                  ),
    ;

    private final String name;
    private final String description;
    private final String metavar;
    private final ArgType type;
    private final ArgumentAction argumentAction;
    private OptionGroup optionGroup = null;

    private Object value = null;


    /**
     * Initialize the TonkaBeanOption with the required parameters.
     *
     * @param name option name on the command line
     * @param description option description within the help menu
     * @param argumentAction argument action to use (flag or option)
     * @param optionGroup OptionGroup that the argument belongs to
     * @param type ArgType to expect from the argument
     */
    TonkaBeanOption(String name, String description, ArgumentAction argumentAction, OptionGroup optionGroup, ArgType type)
    {
        this(name, description, argumentAction, optionGroup, type, null);
    }

    /**
     * Initialize the TonkaBeanOption with the required parameters.
     *
     * @param name option name on the command line
     * @param description option description within the help menu
     * @param argumentAction argument action to use (flag or option)
     * @param optionGroup OptionGroup that the argument belongs to
     * @param type ArgType to expect from the argument
     * @param metavar meta variable to display in the help menu
     */
    TonkaBeanOption(String name, String description, ArgumentAction argumentAction, OptionGroup optionGroup, ArgType type, String metavar)
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
            ExceptionHandler.internalError("Beanshooter.getValue", "ClassCastException was caught.");
        }

        return null;
    }

    /**
     * Returns the value stored within the option. If the value is null, return the specified
     * default value.
     *
     * @return value stored within the option
     */
    @SuppressWarnings("unchecked")
    public <T> T getValue(T def)
    {
        if( value == null )
            return def;

        try {
            return (T)value;

        } catch( ClassCastException e ) {
            ExceptionHandler.internalError("Beanshooter.getValue", "ClassCastException was caught.");
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
