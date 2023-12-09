package eu.tneitzel.beanshooter.exceptions;

/**
 * OpenTypeException is thrown when an exception is encountered within a complex OpenType
 * format like Composite data.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("serial")
public class OpenTypeException extends Exception
{
    public OpenTypeException(String string)
    {
        super(string);
    }
}
