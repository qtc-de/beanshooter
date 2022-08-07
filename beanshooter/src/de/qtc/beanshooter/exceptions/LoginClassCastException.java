package de.qtc.beanshooter.exceptions;

/**
 * LoginClassCastException occur when the JMX server attempts to deserialize a
 * deserialization payload during the login attempt.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class LoginClassCastException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    public LoginClassCastException(Exception e)
    {
        super(e, false);
    }

    public LoginClassCastException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
