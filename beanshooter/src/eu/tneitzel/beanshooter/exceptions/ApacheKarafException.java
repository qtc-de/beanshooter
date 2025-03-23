package eu.tneitzel.beanshooter.exceptions;

/**
 * The ApacheKarafException is thrown when Apache Karaf specific error messages
 * are observed during a login attempt.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ApacheKarafException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    /**
     * Create a new ApacheKarafException by wrapping the actual exception.
     *
     * @param e the actual Karaf related exception.
     */
    public ApacheKarafException(Exception e)
    {
        super(e, false);
    }

    /**
     * Create a new ApacheKarafException by wrapping the actual exception.
     *
     * @param e the actual Karaf related exception.
     * @param showDetails whether to display the original error message or generic error messages
     */
    public ApacheKarafException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
