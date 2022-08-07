package de.qtc.beanshooter.exceptions;

/**
 * UnknownSecurityException is raised when beanshooter obtains an unknown
 * SecurityException during the connection setup.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class UnknownSecurityException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    public UnknownSecurityException(Exception e)
    {
        super(e, false);
    }

    public UnknownSecurityException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
