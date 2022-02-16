package de.qtc.beanshooter.cli;

import java.io.IOException;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.RealmCallback;
import javax.security.sasl.RealmChoiceCallback;

import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.SaslProfileException;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.PluginSystem;

/**
 * When using the JMXMP protocol for connecting to a JMX server, SASL authentication is supported.
 * SASL defines different profiles that can be used for the authentication. This enum contains the
 * different available profile values.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum SASLMechanism {

    PLAIN("SASL/PLAIN"),
    DIGEST("SASL/DIGEST-MD5"),
    CRAM("SASL/CRAM-MD5"),
    GSSAPI("SASL/GSSAPI"),
    NTLM("SASL/NTLM");

    private String profile;

    /**
     * A SASLMechanism is initialized by it's profile name as a String.
     *
     * @param profile name of the corresponding SASL profile.
     */
    SASLMechanism(String profile)
    {
        this.profile = profile;
    }

    /**
     * Returns the name of the corresponding SASL profile. If the --ssl option was used,
     * the profile name is prefixed with "TLS".
     *
     * @return profile name (optionally prefixed with "TLS" if --ssl was used)
     */
    public String getProfile()
    {
        String profile = "";

        if( BeanshooterOption.CONN_SSL.getBool() )
            profile = "TLS ";

        return profile + this.profile;
    }

    /**
     * Configures the specified environment for the usage of SASL. Configures the SASL
     * profile together with the username and password values.
     *
     * @param env JMX environment to set the profile settings on
     * @param username username to use for the authentication
     * @param password password to use for the authentication
     */
    public void init(Map<String, Object> env, String username, String password)
    {
        this.setJmxProfile(env);
        this.setCallbackHandler(env, username, password);
    }

    /**
     * The DIGEST and NTLM SASL mechanisms required a callbackHandler to be configured.
     * This function sets up the corresponding callbackHandler for these cases and assigns
     * it to the specified environment.
     *
     * @param env JMX environment to assign the callbackHandler to
     * @param username username to use for the authentication
     * @param password password to use for the authentication
     */
    public void setCallbackHandler(Map<String,Object> env, String username, String password)
    {
        if( this == DIGEST || this == NTLM )
            env.put("jmx.remote.sasl.callback.handler", new RealmHandler(username, password));
    }

    /**
     * Assign the current profile name to the specified JMX environment.
     *
     * @param env JMX environment to assign the current profile name to
     */
    public void setJmxProfile(Map<String,Object> env)
    {
        env.put("jmx.remote.profiles", this.getProfile());
    }

    /**
     * Returns an String array of the lowercase member names of this enum. This is used
     * within the OptionHandler to create argument choices for SASL mechanims.
     * @return
     */
    public static String[] getMechanisms()
    {
        int ctr = 0;
        String[] mechanisms = new String[5];

        for( SASLMechanism mechanism : SASLMechanism.values() )
        {
            mechanisms[ctr] = mechanism.name().toLowerCase();
            ctr++;
        }

        return mechanisms;
    }

    /**
     * Attempt to autodetect the SASL mechanism of the remote server. This is not 100% reliable.
     * One of the most difficult problems is that SASL authentication seems to ignore the TLS profile
     * in case of incorrect credentials. That means that e.g. the server profile TLS SASL PLAIN reports
     * wrong credentials being used even when the client profile is SASL PLAIN. Only with valid credentials,
     * a reliable enumeration is possible.
     *
     * @param host remote MBean server host
     * @param port remote MBean server port
     * @param env JMX environment to use for the connection
     * @return the SASL mechanism used by the server or null, if the mechanism could not be detected
     */
    public static SASLMechanism detectMechanis(String host, int port, Map<String,Object> env)
    {
        for (SASLMechanism mechanism : SASLMechanism.values())
        {
            BeanshooterOption.CONN_SASL.setValue(mechanism.name().toLowerCase());

            try
            {
                PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);
                return mechanism;
            }

            catch (SaslProfileException e)
            {
                ExceptionHandler.showStackTrace(e);
            }

            catch (AuthenticationException e)
            {
                return mechanism;
            }
        }

        return null;
    }

    /**
     * The DIGEST and NTLM SASL mechanisms require a callbackHandler to be defined for providing
     * the username and the password used during authentication. This class provides a simple
     * implementation.
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    class RealmHandler implements CallbackHandler
    {
        private final String username;
        private final String password;

        /**
         * Initialize the RealmHandler with the username and password that should be used
         * for authentication.
         *
         * @param username username to return to NameCallbacks
         * @param password password to return to PasswordCallbacks
         */
        RealmHandler(String username, String password)
        {
            this.username = username;
            this.password = password;
        }

        /**
         * Handle the different kinds of callbacks.
         */
        @Override
        public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException
        {
            NameCallback nameCallback = null;
            RealmCallback realmCallback = null;
            PasswordCallback passwordCallback = null;
            RealmChoiceCallback realmChoiceCallback = null;

            String realm = "";

            for (int i = 0; i < callbacks.length; i++)
            {
                if (callbacks[i] instanceof NameCallback)
                {
                    nameCallback = (NameCallback)callbacks[i];
                    nameCallback.setName(username);
                }

                else if (callbacks[i] instanceof PasswordCallback)
                {
                    passwordCallback = (PasswordCallback)callbacks[i];
                    passwordCallback.setPassword(password.toCharArray());
                }

                else if (callbacks[i] instanceof RealmCallback)
                {
                    realmCallback = (RealmCallback)callbacks[i];
                    realm = realmCallback.getDefaultText();
                    realmCallback.setText(realm);
                }

                else if (callbacks[i] instanceof RealmChoiceCallback)
                {
                    realmChoiceCallback = (RealmChoiceCallback)callbacks[i];
                    realmChoiceCallback.setSelectedIndex(realmChoiceCallback.getDefaultChoice());
                }

                else
                {
                    throw new UnsupportedCallbackException(callbacks[i]);
                }
            }
        }
    }
}
