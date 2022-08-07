package de.qtc.beanshooter.exceptions;

/**
 * SaslProfileExceptions occur when the client specified SASL profile does not match
 * the server specified one.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SaslMissingException extends SaslProfileException {

    private static final long serialVersionUID = 1L;

    public SaslMissingException(Exception e)
    {
        super(e, false);
    }

    public SaslMissingException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
