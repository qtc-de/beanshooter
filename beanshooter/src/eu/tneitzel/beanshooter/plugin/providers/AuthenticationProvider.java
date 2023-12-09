package eu.tneitzel.beanshooter.plugin.providers;

import java.util.HashMap;
import java.util.Map;

import javax.management.remote.JMXConnector;
import javax.rmi.ssl.SslRMIClientSocketFactory;

import eu.tneitzel.beanshooter.operation.BeanshooterOption;
import eu.tneitzel.beanshooter.plugin.IAuthenticationProvider;

/**
 * The default implementation for the IAuthenticationProvider interface creates an JMX environment that contains
 * the JMXConnector.CREDENTIALS key with an associated String array containing username and password. Additionally,
 * if --ssl was used, the com.sun.jndi.rmi.factory.socket property is set.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class AuthenticationProvider implements IAuthenticationProvider
{
    /**
     * Authentication to JMX endpoints is usually handled using a map that contains the authentication
     * parameters. This function is used to prepare such a map by using an explicitly defiend username
     * and password.
     *
     * @param username the desired username for JMX authentication
     * @param password the desired password for JMX authentication
     * @return environment that should be used during the newClient call
     */
    public Map<String,Object> getEnv(String username, String password)
    {
        HashMap<String,Object> env = new HashMap<String,Object>();

        if(BeanshooterOption.CONN_SSL.getBool())
            env.put("com.sun.jndi.rmi.factory.socket", new SslRMIClientSocketFactory());

        if(username != null && password != null)
            env.put(JMXConnector.CREDENTIALS, new String[] {username, password});

        return env;
    }
}
