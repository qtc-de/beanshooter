package de.qtc.beanshooter.exceptions;

/**
 * The ApacheKarafException is thrown when Apache Karaf specific error messages
 * are observed during a login attempt.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ApacheKarafException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    public ApacheKarafException(Exception e)
    {
        super(e, false);
    }

    public ApacheKarafException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
