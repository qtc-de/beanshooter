package eu.tneitzel.beanshooter.exceptions;

/**
 * WrongCredentialExceptions are raised when beanshooter attempts a login with wrong
 * credentials.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class WrongCredentialsException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    public WrongCredentialsException(Exception e)
    {
        super(e, false);
    }

    public WrongCredentialsException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
