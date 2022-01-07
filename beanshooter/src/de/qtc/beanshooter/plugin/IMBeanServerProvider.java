package de.qtc.beanshooter.plugin;

import java.util.Map;

import javax.management.MBeanServerConnection;

/**
 * beanshooter supports different ways for obtaining a connection to an remote MBeanServer (e.g. rmi vs jmxmp).
 * The different providers need to implement this interface. Furthermore, custom plugins can implement this
 * interface to overwrite the default behavior.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IMBeanServerProvider
{
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env);
}