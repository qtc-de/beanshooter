package de.qtc.beanshooter.operation;

import de.qtc.beanshooter.cli.ArgType;
import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.cli.OptionGroup;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import net.sourceforge.argparse4j.impl.Arguments;
import net.sourceforge.argparse4j.inf.ArgumentAction;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * All available top-level beanshooter options are defined in this enum. The enum stores the option
 * names, their description, the information whether they are boolean or store values and an optional
 * meta variable. Additionally, each Option is assigned to an OptionGroup. This is used for grouping
 * related arguments in the help menu of beanshooter.
 *
 * Options are not assigned to operations here. This is done within the BeanshooterOperation class.
 * The top-level options are supplemented by options for the MBeans that beanshooter can deploy. These
 * are defined in the respective MBean classes.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum BeanshooterOption implements Option {

    GLOBAL_CONFIG("--config",
                  "path to a configuration file",
                  Arguments.store(),
                  OptionGroup.GENERAL,
                  ArgType.STRING,
                  "config-file"),

    GLOBAL_VERBOSE("--verbose",
                   "enable verbose output",
                   Arguments.storeTrue(),
                   OptionGroup.GENERAL,
                   ArgType.BOOL),

    GLOBAL_PLUGIN("--plugin",
                  "file system path to a beanshooter plugin",
                  Arguments.store(),
                  OptionGroup.GENERAL,
                  ArgType.STRING,
                  "plugin-file"),

    GLOBAL_NO_COLOR("--no-color",
                    "disable colored output",
                    Arguments.storeTrue(),
                    OptionGroup.GENERAL,
                    ArgType.BOOL),

    GLOBAL_STACK_TRACE("--stack-trace",
                       "display stack traces for caught exceptions",
                       Arguments.storeTrue(),
                       OptionGroup.GENERAL,
                       ArgType.BOOL),

    TARGET_HOST("host",
                "target host",
                Arguments.store(),
                OptionGroup.NONE,
                ArgType.STRING,
                "host"),

    TARGET_PORT("port",
                "target port",
                Arguments.store(),
                OptionGroup.NONE,
                ArgType.INT,
                "port"),

    TARGET_BOUND_NAME("--bound-name",
                      "target bound name within an RMI registry",
                      Arguments.store(),
                      OptionGroup.TARGET,
                      ArgType.STRING,
                      "name"),

    TARGET_OBJID_SERVER("--objid-server",
                        "target ObjID for an RMIServer remote object",
                        Arguments.store(),
                        OptionGroup.TARGET,
                        ArgType.STRING,
                        "objid"),

    TARGET_OBJID_CONNECTION("--objid-connection",
                            "target ObjID for an RMIConnection remote object",
                            Arguments.store(),
                            OptionGroup.TARGET,
                            ArgType.STRING,
                            "objid"),

    CONN_FOLLOW("--follow",
                "follow redirects to different servers",
                Arguments.storeTrue(),
                OptionGroup.CONNECTION,
                ArgType.BOOL),

    CONN_SSL("--ssl",
             "use SSL for connections",
             Arguments.storeTrue(),
             OptionGroup.CONNECTION,
             ArgType.BOOL),

    CONN_JMXMP("--jmxmp",
               "use JMXMP for JMX communication",
               Arguments.storeTrue(),
               OptionGroup.CONNECTION,
               ArgType.BOOL),

    CONN_USER("--username",
              "username to use for JMX authentication",
              Arguments.store(),
              OptionGroup.CONNECTION,
              ArgType.STRING,
              "user"),

    CONN_PASS("--password",
              "password to use for JMX authentication",
              Arguments.store(),
              OptionGroup.CONNECTION,
              ArgType.STRING,
             "pass"),

    CONN_JNDI("--jndi",
              "JNDI connection string to use for the connection",
              Arguments.store(),
              OptionGroup.CONNECTION,
              ArgType.STRING,
              "jndi"),

    CONN_JOLOKIA("--jolokia",
            "Connect via Jolokia HTTP based protocol",
            Arguments.storeTrue(),
            OptionGroup.CONNECTION,
            ArgType.BOOL
            ),

    CONN_JOLOKIA_ENDPOINT("--jolokia-endpoint",
            "HTTP endpoint for Jolokia (default: /jolokia/)",
            Arguments.store(),
            OptionGroup.CONNECTION,
            ArgType.STRING,
            "endpoint"
            ),

    CONN_JOLOKIA_PROXY("--jolokia-proxy",
            "Backend JMX target when Jolokia operates in proxy mode",
            Arguments.store(),
            OptionGroup.CONNECTION,
            ArgType.STRING,
            "jmxurl"
            ),

    CONN_JOLOKIA_PROXY_USER("--jolokia-proxy-user",
            "Backend JMX user when Jolokia operates in proxy mode",
            Arguments.store(),
            OptionGroup.CONNECTION,
            ArgType.STRING,
            "user"
            ),

    CONN_JOLOKIA_PROXY_PASS("--jolokia-proxy-pass",
            "Backend JMX password when Jolokia operates in proxy mode",
            Arguments.store(),
            OptionGroup.CONNECTION,
            ArgType.STRING,
            "password"
            ),

    EXPORT_DIR("--export-dir",
            "export tonka bean and mlet file to the specified dir",
            Arguments.store(),
            OptionGroup.ACTION,
            ArgType.STRING,
             "dir"
            ),

     EXPORT_JAR("--export-jar",
                "export the tonka bean to the specified filename",
                Arguments.store(),
                OptionGroup.ACTION,
                ArgType.STRING,
                 "filename"
                ),

     EXPORT_MLET("--export-mlet",
                 "export an MLet HTML file to the specified location",
                 Arguments.store(),
                 OptionGroup.ACTION,
                 ArgType.STRING,
                 "filename"
                 ),

     EXPORT_URL("--stager-url",
                "URL of the stager server to use within the MLet HTML file",
                Arguments.store(),
                OptionGroup.ACTION,
                ArgType.STRING,
                "url"
                ),

    DEPLOY_NO_STAGER("--no-stager",
                     "do not launch the stager HTTP server",
                     Arguments.storeTrue(),
                     OptionGroup.ACTION,
                     ArgType.BOOL),

    DEPLOY_STAGER_URL("--stager-url",
                      "url of the stager server",
                      Arguments.store(),
                      OptionGroup.ACTION,
                      ArgType.STRING,
                      "URL"),

    DEPLOY_STAGER_PORT("--stager-port",
                       "TCP port to start the stager on",
                       Arguments.store(),
                       OptionGroup.ACTION,
                       ArgType.INT,
                       "port"),

    DEPLOY_STAGER_ADDR("--stager-host",
                       "IP address to start the stager on",
                       Arguments.store(),
                       OptionGroup.ACTION,
                       ArgType.STRING,
                       "addr"),

    DEPLOY_BEAN_CLASS("classname",
                      "classname of the MBean to deploy",
                      Arguments.store(),
                      OptionGroup.ACTION,
                      ArgType.STRING
                      ),

    DEPLOY_BEAN_NAME("object-name",
                     "object name of the MBean to deploy",
                     Arguments.store(),
                     OptionGroup.ACTION,
                     ArgType.STRING
                     ),

    DEPLOY_JAR_FILE("--jar-file",
                    "jar archive to deploy",
                    Arguments.store(),
                    OptionGroup.ACTION,
                    ArgType.STRING,
                    "path"),

    UNDEPLOY_BEAN_NAME("object-name",
                     "object name of the MBean to remove",
                     Arguments.store(),
                     OptionGroup.ACTION,
                     ArgType.STRING,
                     "name"),

    BRUTE_THREADS("--threads",
                  "maximum number of threads (default: 5)",
                  Arguments.store(),
                  OptionGroup.ACTION,
                  ArgType.INT,
                  "threads"),

    BRUTE_FIRST("--first",
                "stop after finding a valid credential pair",
                Arguments.storeTrue(),
                OptionGroup.ACTION,
                ArgType.BOOL),

    SERIAL_GADGET_NAME("gadget",
                         "gadget to use for the deserialization attack",
                         Arguments.store(),
                         OptionGroup.ACTION,
                         ArgType.STRING,
                         "gadget"),

    SERIAL_GADGET_CMD("cmd",
                        "gadget command to use for the deserialization attack",
                        Arguments.store(),
                        OptionGroup.ACTION,
                        ArgType.STRING,
                        "cmd"),

    SERIAL_NO_CANARY("--no-canary",
            "do not use a canary during deserialization attacks",
            Arguments.storeTrue(),
            OptionGroup.ACTION,
            ArgType.STRING
            ),

    SERIAL_PREAUTH("--preauth",
                   "attempt pre authentication deserialization",
                   Arguments.storeTrue(),
                   OptionGroup.ACTION,
                   ArgType.BOOL
                   ),

    BRUTE_USER("--username",
                 "username for the bruteforce attack",
                  Arguments.store(),
                  OptionGroup.ACTION,
                  ArgType.STRING,
                  "name"),

    BRUTE_PASSWORD("--password",
                        "password for the bruteforce attack",
                        Arguments.store(),
                        OptionGroup.ACTION,
                        ArgType.STRING,
                      "password"),

    BRUTE_USER_FILE("--username-file",
                        "password file for the bruteforce attack",
                        Arguments.store(),
                        OptionGroup.ACTION,
                        ArgType.STRING,
                        "path"),

    BRUTE_PW_FILE("--password-file",
                  "password file for the bruteforce attack",
                  Arguments.store(),
                  OptionGroup.ACTION,
                  ArgType.STRING,
                  "path"),

    INVOKE_OBJ_NAME("object-name",
                    "ObjectName of the targeted MBean",
                    Arguments.store(),
                    OptionGroup.ACTION,
                    ArgType.STRING,
                    "objname"),

    INVOKE_METHOD_ARGS("arg",
                       "argument to use for the call",
                       Arguments.store(),
                       OptionGroup.ACTION,
                       ArgType.ARRAY,
                       "arg"),

    INVOKE_METHOD("--signature",
                  "the method to call on the targeted object name",
                  Arguments.store(),
                  OptionGroup.ACTION,
                  ArgType.STRING,
                  "sig"
                  ),

    INVOKE_NO_WRAP("--no-wrap",
                   "prevent autowrapping of primitive types",
                   Arguments.storeTrue(),
                   OptionGroup.ACTION,
                   ArgType.BOOL
                   ),

    JOLOKIA_HOST("proxy-host",
                 "target host to trigger the outbound connection to",
                 Arguments.store(),
                 OptionGroup.ACTION,
                 ArgType.STRING,
                 "proxy-host"
                ),

    JOLOKIA_PORT("proxy-port",
                 "target port to trigger the outbound connection to",
                 Arguments.store(),
                 OptionGroup.ACTION,
                 ArgType.INT,
                 "proxy-port"
                ),

    JOLOKIA_LDAP("--ldap",
            "trigger an outbound LDAP connection instead of RMI",
            Arguments.storeTrue(),
            OptionGroup.ACTION,
            ArgType.BOOL
            ),

    JOLOKIA_LOOKUP("--lookup",
            "use the specified name for the JNDI lookup",
            Arguments.store(),
            OptionGroup.ACTION,
            ArgType.STRING,
            "name"
            ),

    OBJ_NAME("object-name",
             "the ObjectName to perform the operation on",
             Arguments.store(),
             OptionGroup.ACTION,
             ArgType.STRING
            ),

    ATTR_ATTRIBUTE("attribute",
                   "the attribute to operate on",
                   Arguments.store(),
                   OptionGroup.ACTION,
                   ArgType.STRING
                  ),

    ATTR_VALUE("value",
               "the attribute value to set",
               Arguments.store(),
               OptionGroup.ACTION,
               ArgType.STRING
              ),

    ATTR_TYPE("--type",
              "the type of the attribute",
              Arguments.store(),
              OptionGroup.ACTION,
              ArgType.STRING
             ),

    ATTR_WRITEABLE("--writable",
                   "only list writable attributes",
                   Arguments.storeTrue(),
                   OptionGroup.ACTION,
                   ArgType.BOOL
                   ),

    ATTR_HARVEST("--harvest",
                 "only show attributes that match keywords",
                 Arguments.storeTrue(),
                 OptionGroup.ACTION,
                 ArgType.BOOL
                   ),

    ATTR_KEYWORDS("--keywords",
                   "space separated list of keywords",
                   Arguments.store(),
                   OptionGroup.ACTION,
                   ArgType.STRING
                    ),

    ATTR_METHOD_KEYWORDS("--method-keywords",
                               "space separated list of keywords",
                               Arguments.store(),
                               OptionGroup.ACTION,
                               ArgType.STRING
                            ),

    MODEL_OBJ_NAME("object-name",
               "ObjectName for the newly deployed RequiredModelMBean",
               Arguments.store(),
               OptionGroup.ACTION,
               ArgType.STRING
              ),

    MODEL_CLASS_NAME("class-name",
            "Class that should be made accessible via the deployed RequiredModelMBean",
            Arguments.store(),
            OptionGroup.ACTION,
            ArgType.STRING
              ),

    MODEL_RESOURCE("resource",
                      "managed resource for the RequiredModelMBean",
                      Arguments.store(),
                      OptionGroup.ACTION,
                      ArgType.STRING
                  ),

    MODEL_ALL_METHODS("--all-methods",
               "also deploy methods with non serializable parameters",
               Arguments.storeTrue(),
               OptionGroup.ACTION,
               ArgType.BOOL
              ),

    MODEL_SIGNATURE("--signature",
            "create a RequiredModelMBean with the specified method signature",
            Arguments.store(),
            OptionGroup.ACTION,
            ArgType.STRING
              ),

    STANDARD_OPERATION("operation",
             "operation to execute via StandardMBean",
             Arguments.store(),
             OptionGroup.ACTION,
             ArgType.STRING
               ),

    STANDARD_OPERATION_ARGS("args",
              "arguments for the operation to execute via StandardMBean",
              Arguments.store(),
              OptionGroup.ACTION,
              ArgType.STRING
                ),

    STANDARD_EXEC_ARRAY("--exec-array",
               "space-split the command in three parts and pass it as array to Runtime.exec",
               Arguments.storeTrue(),
               OptionGroup.ACTION,
               ArgType.BOOL
                 ),

    MODEL_SIGNATURE_FILE("--signature-file",
            "create a RequiredModelMBean with method signatures from a file",
            Arguments.store(),
            OptionGroup.ACTION,
            ArgType.STRING
              ),

    STAGER_HOST("host",
                "the IP address to listen on",
                Arguments.store(),
                OptionGroup.ACTION,
                ArgType.STRING
                ),

    STAGER_PORT("port",
                "the port to start the stager on",
                Arguments.store(),
                OptionGroup.ACTION,
                ArgType.INT
                ),

    CONN_SASL("--sasl",
              "SASL mechanism to use for the connection",
              Arguments.store(),
              OptionGroup.CONNECTION,
              ArgType.STRING,
              "method"),

    NO_PROGRESS("--no-progress",
                "do not display a progress bar",
                Arguments.storeTrue(),
                OptionGroup.ACTION,
                ArgType.BOOL
                ),

    LIST_FILTER_CLASS("--class-filter",
                      "only display MBeans implementing classes that contain the specified string",
                      Arguments.store(),
                      OptionGroup.ACTION,
                      ArgType.STRING,
                          "filter"
                     ),

    LIST_FILTER_OBJ("--obj-filter",
                      "only display MBeans with an ObjectName containing the specified string",
                      Arguments.store(),
                      OptionGroup.ACTION,
                      ArgType.STRING,
                      "filter"
                    ),

    YSO("--yso",
        "location of ysoserial.jar for deserialization attacks",
        Arguments.store(),
        OptionGroup.ACTION,
        ArgType.STRING,
        "yso-path");

    private final String name;
    private final String description;
    private final String metavar;
    private final ArgType type;
    private final ArgumentAction argumentAction;
    private OptionGroup optionGroup = null;

    private Object value = null;

    /**
     * Initializes an enum field with the corresponding Option name, the Option description the argument action,
     * which decides whether the option is boolean or expects a value and an RMGOptionGroup, that is used to
     * group options within command line help.
     *
     * @param name Name of the option. As used on the command line
     * @param description Description that is shown within the help menu
     * @param argumentAction argparse4j ArgumentAction for this option
     * @param optionGroup Logical group to display the argument in when printing the help menu
     * @param type expected argument type
     */
    BeanshooterOption(String name, String description, ArgumentAction argumentAction, OptionGroup optionGroup, ArgType type)
    {
        this(name, description, argumentAction, optionGroup, type, null);
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
     * @param type expected argument type
     * @param metavar Meta name for the expected option value
     */
    BeanshooterOption(String name, String description, ArgumentAction argumentAction, OptionGroup optionGroup, ArgType type, String metavar)
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
