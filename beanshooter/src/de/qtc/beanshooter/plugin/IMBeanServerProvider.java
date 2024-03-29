package de.qtc.beanshooter.plugin;

import java.util.Map;

import javax.management.MBeanServerConnection;

import org.jolokia.client.exception.J4pRemoteException;

import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.PluginException;

/**
 * beanshooter supports different ways for obtaining a connection to an remote MBeanServer (e.g. rmi vs jmxmp).
 * The different providers need to implement this interface. Furthermore, plugins can implement this interface
 * to provide additional ways to connect to a remote MBeanServer.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IMBeanServerProvider
{
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env) throws AuthenticationException, PluginException, J4pRemoteException;
}
