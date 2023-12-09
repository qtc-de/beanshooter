package eu.tneitzel.beanshooter.exceptions;

/**
 * SaslProfileExceptions occur when the client specified SASL profile does not match
 * the server specified one.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SaslProfileException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    public SaslProfileException(Exception e)
    {
        super(e, false);
    }

    public SaslProfileException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
