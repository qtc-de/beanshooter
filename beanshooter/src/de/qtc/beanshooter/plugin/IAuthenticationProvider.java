package de.qtc.beanshooter.plugin;

import java.util.Map;

/**
 * Create the JMX environment that is used during the newClient call. The default JMX implementation
 * expects the returned Map to contain the key JMXConnector.CREDENTIALS with an associated String array
 * containing the username and the password. However, custom implementations may expect a different
 * format. Therefore, providing the Map through the plugin system allows users to modify the default
 * behavior.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IAuthenticationProvider
{
    public Map<String,Object> getEnv(String username, String password);
}
