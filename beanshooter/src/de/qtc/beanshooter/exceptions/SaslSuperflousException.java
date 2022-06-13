package de.qtc.beanshooter.exceptions;

/**
 * SaslProfileExceptions occur when the client specified SASL profile does not match
 * the server specified one.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SaslSuperflousException extends SaslProfileException {

    private static final long serialVersionUID = 1L;

    public SaslSuperflousException(Exception e)
    {
        super(e, false);
    }

    public SaslSuperflousException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
