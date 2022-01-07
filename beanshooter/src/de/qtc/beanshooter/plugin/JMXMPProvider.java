package de.qtc.beanshooter.plugin;

import java.util.Map;

import javax.management.MBeanServerConnection;

/**
 * The JMXMP provider provides MBeanServerConnections by using the JMXMP protocol.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class JMXMPProvider implements IMBeanServerProvider {

    @Override
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env) {
        // TODO Auto-generated method stub
        return null;
    }

}
