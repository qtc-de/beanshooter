package com.sun.jdmk.security.sasl.callbacks;

import java.io.IOException;
import java.util.HashMap;

import javax.management.remote.extension.JMXMPSaslLifecycleListener;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.RealmCallback;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import com.sun.jdmk.security.sasl.AuthenticateCallback;

public class AuthenticationCallBackHandler implements CallbackHandler {

    private HashMap<String,String> credentials = new HashMap<String,String>();
    private static final Log log = LogFactory.getLog(JMXMPSaslLifecycleListener.class);

    public AuthenticationCallBackHandler() {
         this.credentials.put("controlRole", "control");
         this.credentials.put("monitorRole", "monitor");
    }

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

                log.info("Got AuthorizeCallback for '" + authid + ":" + authzid + "'");

                if (authid.equals(authzid)) {
                    authorize.setAuthorized(true);
                }

            } else if (callbacks[i] instanceof AuthenticateCallback) {

                authenticate = (AuthenticateCallback)callbacks[i];

                username = authenticate.getAuthenticationID();
                password = new String(authenticate.getPassword());
                String pw = credentials.get(username);

                log.info("Got AuthenticatedCallback for '" + username + ":" + password + "'");

                if(pw == null) {
                    log.info("Username '" + username + "' is unknown.");
                    authenticate.setAuthenticated(false);
                } else if (pw.equals(password)) {
                    authenticate.setAuthenticated(true);
                }

            } else if (callbacks[i] instanceof NameCallback) {

                name = (NameCallback)callbacks[i];
                username = name.getDefaultName();

                log.info("Got NameCallback for '" + username +"'");
                name.setName(username);

            } else if (callbacks[i] instanceof PasswordCallback) {

                pass = (PasswordCallback)callbacks[i];
                password = credentials.get(username);

                if(password == null) {
                    log.info("Username '" + username + "' is unknown.");
                    pass.setPassword("backdoor :O".toCharArray());
                } else {
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
