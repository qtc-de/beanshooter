package de.qtc.beanshooter.exceptions;

/**
 * The GlassFishException is thrown when GlassFish specific error messages
 * are observed during a JMX login attempt.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class GlassFishException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    public GlassFishException(Exception e)
    {
        super(e, false);
    }

    public GlassFishException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }
}
