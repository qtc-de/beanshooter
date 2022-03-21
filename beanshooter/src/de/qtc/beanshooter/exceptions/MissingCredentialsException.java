package de.qtc.beanshooter.exceptions;

/**
 * MissingCredentialsExceptions are raised when beanshooter attempts a login without
 * credentials, but the server requires authentication.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MissingCredentialsException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    public MissingCredentialsException(Exception e)
    {
        super(e, false);
    }

    public MissingCredentialsException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
