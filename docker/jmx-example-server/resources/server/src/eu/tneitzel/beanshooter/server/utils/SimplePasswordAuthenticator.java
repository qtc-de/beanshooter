package eu.tneitzel.beanshooter.server.utils;

import java.util.HashMap;
import java.util.Map;
import java.util.Map.Entry;

import javax.management.remote.JMXAuthenticator;
import javax.security.auth.Subject;

/**
 * JMX endpoints can be protected by classes implementing the JMXAuthenticator interface.
 * This class implements a simple password based authentication that can be plugged in a
 * JMX server.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SimplePasswordAuthenticator implements JMXAuthenticator {

    private Map<String,String> credentials;

    /**
     * Create a SimplePasswordAuthenticator with an empty credentials map.
     */
    public SimplePasswordAuthenticator()
    {
        this.credentials = new HashMap<String,String>();
    }

    /**
     * Add a credential to the credential map.
     *
     * @param username username to add
     * @param password password to add
     */
    public void addCredential(String username, String password)
    {
        this.credentials.put(username, password);
    }

    /**
     * Check whether the incoming credential object has the correct format and contains
     * a username and password combination that is also available in our credential map.
     */
    @Override
    public Subject authenticate(Object credentials)
    {
        Subject subject = null;

        if( credentials == null )
            throw new SecurityException("Authentication required.");

        if( credentials.getClass() != String[].class )
            throw new SecurityException("Invalid credential type.");

        String[] creds = (String[])credentials;

        if( creds.length != 2 )
            throw new SecurityException("Invalid credential type.");

        String username = creds[0];
        String password = creds[1];

        for( Entry<String,String> entry : this.credentials.entrySet() )
        {
            if( entry.getKey().equals(username) && entry.getValue().equals(password) )
                subject = new Subject();
        }

        if( subject == null )
            throw new SecurityException("Bad credentials");

        return subject;
    }
}
