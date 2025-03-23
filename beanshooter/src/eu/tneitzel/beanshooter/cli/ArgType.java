package eu.tneitzel.beanshooter.cli;

/**
 * The ArgType enum contains the possible argument types that may be passed on the
 * command line by the invoking user.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum ArgType
{
    /** Integer like arguments **/
    INT,
    /** Boolean like arguments **/
    BOOL,
    /** String like arguments **/
    STRING,
    /** Array like arguments **/
    ARRAY;
}
