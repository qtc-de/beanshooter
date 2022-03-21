package de.qtc.beanshooter.exceptions;

import de.qtc.beanshooter.io.Logger;

/**
 * A failed authentication attempt on a JMX endpoint needs to be handled in different ways
 * depending on the specified action. beanshooter raises an AuthenticationException for these
 * cases, which contains the original exception as a class attribute. The function that performed
 * the login attempt can then handle it in the required way.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class AuthenticationException extends Exception {

    protected final Exception origException;
    protected final boolean showDetails;

    private static final long serialVersionUID = 1L;

    /**
     * Create a new instance containing the original exception as an attribute.
     *
     * @param e original exception.
     */
    public AuthenticationException(Exception e)
    {
        this(e, false);
    }

    /**
     * For failed login attempts, the default error messages displayed by most actions contains
     * a generic reason e.g. "wrong credentials". In the case of SASL mismatches, the message contained
     * in the original exception can be useful (e.g. "Client used no profile but server expects SASL PLAIN").
     * When showDetails is set to true, the message from the original exception is displayed under the
     * generic error message.
     *
     * @param e original exception
     * @param showDetails whether to display the original error message unde generic error messages
     */
    public AuthenticationException(Exception e, boolean showDetails)
    {
        this.origException = e;
        this.showDetails = showDetails;
    }

    /**
     * Return the original exception.
     *
     * @return original exception
     */
    public Exception getOriginalException()
    {
        return origException;
    }

    /**
     * Print the message of the original exception in a formatted way.
     */
    public void showDetails()
    {
        if( showDetails )
            Logger.eprintlnMixedYellow("Original Exception:", origException.getMessage());
    }

    /**
     * Override the original printStackTrace method to print the stack trace of the original
     * Exception.
     */
    public void printStackTrace()
    {
        origException.printStackTrace();
    }

    /**
     * Override the original getMessage method to return the message of the original
     * Exception.
     */
    public String getMessage()
    {
        return origException.getMessage();
    }
}
