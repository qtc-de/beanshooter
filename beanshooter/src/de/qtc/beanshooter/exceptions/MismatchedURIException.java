package de.qtc.beanshooter.exceptions;

/**
 * MismatchedURIExceptions occur when the DIGEST-MD5 SASL mechanism was used and
 * the specified server name does not match the actual hostname.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MismatchedURIException extends AuthenticationException {

    private static final long serialVersionUID = 1L;

    public MismatchedURIException(Exception e)
    {
        super(e, false);
    }

    public MismatchedURIException(Exception e, boolean showDetails)
    {
        super(e, showDetails);
    }

    public Exception getOriginalException()
    {
        return origException;
    }

    public String getUri()
    {
        String message = getMessage();
        message = message.substring(message.lastIndexOf(" ") + 1);
        return message.replace("jmxmp/", "");
    }
}
