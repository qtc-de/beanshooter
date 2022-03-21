package de.qtc.beanshooter.exceptions;

/**
 * MismatchedURIExceptions occur when the DIGEST-MD5 SASL mechanism was used and
 * the specified server name does not match the actual hostname.
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
