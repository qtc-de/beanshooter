package de.qtc.beanshooter.exceptions;

import de.qtc.beanshooter.io.Logger;

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

    public void printStackTrace()
    {
        if (origException.getMessage().contains("AdminLoginModule$PrincipalCallback"))
        {
            Logger.lineBreak();
            Logger.printlnMixedBlue("The following stacktrace might be misleading. See", "https://github.com/eclipse-ee4j/glassfish/issues/24223");
            Logger.printlnMixedYellow("Summarized: The error is probably caused by", "missing or invalid", "credentials.");
            Logger.lineBreak();
        }

        origException.printStackTrace();
    }
}
