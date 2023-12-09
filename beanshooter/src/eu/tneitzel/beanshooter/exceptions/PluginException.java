package eu.tneitzel.beanshooter.exceptions;

/**
 * Can be raised by plugins. Beanshooter always aborts upon encountering such an exception.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class PluginException extends Exception
{
    private static final long serialVersionUID = 1L;
    protected final Exception origException;

      public PluginException()
      {
          this(null, null);
      }

      public PluginException(String message)
      {
         this(message, null);
      }

      public PluginException(String message, Exception e)
      {
         super(message);
         origException = e;
      }
}
