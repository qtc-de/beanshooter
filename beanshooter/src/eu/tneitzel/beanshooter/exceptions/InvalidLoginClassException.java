package eu.tneitzel.beanshooter.exceptions;

/**
 * InvalidLoginClassException occur when a deserilization payload was used during a login attempt
 * and the server rejected the invalid login class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class InvalidLoginClassException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    public InvalidLoginClassException(Exception e)
    {
        super(e, false);
    }

    public InvalidLoginClassException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
