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
        PasswordCallback pass = null;
        AuthorizeCallback authorize = null;
        AuthenticateCallback authenticate = null;

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

                String username = authenticate.getAuthenticationID();
                String password = new String(authenticate.getPassword());
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
                log.info("Got Name for '" + name.getDefaultName() +"'");

                name.setName("controlRole");

            } else if (callbacks[i] instanceof PasswordCallback) {

                pass = (PasswordCallback)callbacks[i];
                pass.setPassword("control".toCharArray());

            } else {
                throw new UnsupportedCallbackException(callbacks[i]);
            }
        }
    }
}
