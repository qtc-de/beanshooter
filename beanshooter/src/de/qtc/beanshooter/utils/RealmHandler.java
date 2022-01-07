package de.qtc.beanshooter.utils;

import java.io.IOException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;

/**
 * The RealmHandler class is required to handle authentication in case of JMXMP connections.
 * The JMXMP connector expects credentials to be obtained by a callback function that is contained
 * in this handler. Username and password are stored as static values and are returned by the
 * handle function.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RealmHandler implements CallbackHandler {

    public static String username = "";
    public static String password = "";

    /**
     * Handles the callback and returns the stored username and password in the desired format.
     */
    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {

        NameCallback nameCallback = null;
        RealmCallback realmCallback = null;
        PasswordCallback passwordCallback = null;
        RealmChoiceCallback realmChoiceCallback = null;

        String realm = "";

        for (int i = 0; i < callbacks.length; i++) {

            if (callbacks[i] instanceof NameCallback) {

                nameCallback = (NameCallback)callbacks[i];
                nameCallback.setName(username);

            } else if (callbacks[i] instanceof PasswordCallback) {

                passwordCallback = (PasswordCallback)callbacks[i];
                passwordCallback.setPassword(password.toCharArray());

            } else if (callbacks[i] instanceof RealmCallback) {

                realmCallback = (RealmCallback)callbacks[i];
                realm = realmCallback.getDefaultText();
                realmCallback.setText(realm);

            } else if (callbacks[i] instanceof RealmChoiceCallback) {

                realmChoiceCallback = (RealmChoiceCallback)callbacks[i];
                realmChoiceCallback.setSelectedIndex(realmChoiceCallback.getDefaultChoice());

            } else {
                throw new UnsupportedCallbackException(callbacks[i]);
            }
        }
    }
}
