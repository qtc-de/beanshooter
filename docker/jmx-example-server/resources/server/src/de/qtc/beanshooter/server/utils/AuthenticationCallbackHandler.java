package de.qtc.beanshooter.server.utils;

import java.io.IOException;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import com.sun.jdmk.security.sasl.AuthenticateCallback;

/**
 * SASL protected JMXMP endpoints require a CallbackHandlers to obtain the credentials from.
 * This class implements a CallnbackHandler that stores usernames and passwords and returns
 * them accordingly.
 * 
 * @author Tobias Neitzel (@qtc_de)
 */
public class AuthenticationCallbackHandler implements CallbackHandler {

    private final Map<String,String> credentials;

    /**
     * Create an AuthenticationCallbackHandler and store some credentials within of it.
     * Credentials should be contained within a Map with <username,password> format.
     * 
     * @param credentials map that contains the available credentials.
     */
    public AuthenticationCallbackHandler(Map<String,String> credentials)
    {
         this.credentials = credentials;
    }

    /**
     * Sets the username or password according to the incoming callback. If the incoming callback
     * is a RealmCallback, set iinsecure.dev as realm.
     */
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        NameCallback name = null;
        RealmCallback realm = null;
        PasswordCallback pass = null;
        AuthorizeCallback authorize = null;
        AuthenticateCallback authenticate = null;

        String username = "";
        String password = "";

        for (int i = 0; i < callbacks.length; i++) {

            if (callbacks[i] instanceof AuthorizeCallback) {

                authorize = (AuthorizeCallback)callbacks[i];

                String authid = authorize.getAuthenticationID();
                String authzid = authorize.getAuthorizationID();

                Logger.printlnMixedYellow("Got AuthorizeCallback for", authid + ":" + authzid);

                if (authid.equals(authzid)) {
                    authorize.setAuthorized(true);
                }

            } else if (callbacks[i] instanceof AuthenticateCallback) {

                authenticate = (AuthenticateCallback)callbacks[i];

                username = authenticate.getAuthenticationID();
                password = new String(authenticate.getPassword());
                String pw = credentials.get(username);

                Logger.printlnMixedYellow("Got AuthenticateCallback for", username + ":" + password);

                if(pw == null)
                {
                    Logger.printlnMixedYellow("Username", username, "is not known.");
                    authenticate.setAuthenticated(false);
                } 
                else if (pw.equals(password)) 
                {
                    authenticate.setAuthenticated(true);
                }

            } else if (callbacks[i] instanceof NameCallback) {

                name = (NameCallback)callbacks[i];
                username = name.getDefaultName();

                Logger.printlnMixedYellow("Got NameCallback for", username);
                name.setName(username);

            } else if (callbacks[i] instanceof PasswordCallback) {

                pass = (PasswordCallback)callbacks[i];
                password = credentials.get(username);
                
                Logger.println("Got Password callback.");

                if(password == null) {
                	
                    Logger.printlnMixedYellow("Username", username, "is not known.");
                    pass.setPassword("backdoor :O".toCharArray());
                    
                } else {
                    Logger.printlnMixedYellow("Setting password", password);
                    pass.setPassword(password.toCharArray());
                }

            } else if (callbacks[i] instanceof RealmCallback) {

                realm = (RealmCallback)callbacks[i];
                realm.setText("iinsecure.dev");

            } else {
                throw new UnsupportedCallbackException(callbacks[i]);
            }
        }
    }
}