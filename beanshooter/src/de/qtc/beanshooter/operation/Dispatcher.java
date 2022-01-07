package de.qtc.beanshooter.operation;

import java.util.Map;

import javax.management.MBeanServerConnection;
import javax.management.ObjectName;

import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.plugin.PluginSystem;
import de.qtc.beanshooter.utils.Utils;

/**
 * The dispatcher class is responsible for dispatching the different beanshooter actions.
 * This class implements the main logic of the different beanshooter actions.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher {

    private MBeanServerClient client;
    private MBeanServerConnection conn;

    /**
     * Obtain an MBeanServer connection. The connection is created using the PluginSystem
     * and cached within the Dispatcher class. Followup calls will use the cached MBeanServerConnection.
     *
     * @return MBeanServerConnection to the remote MBeanServer
     */
    private MBeanServerConnection getMBeanServerConnection()
    {
        if( conn != null )
            return conn;

        String host = Option.require(Option.TARGET_HOST);
        int port = Option.require(Option.TARGET_PORT);
        Map<String,Object> env = Option.getEnv();

        conn = PluginSystem.getMBeanServerConnection(host, port, env);
        return conn;
    }

    /**
     * Obtain an MBeanServer connection. The connection is created using the PluginSystem
     * and cached within the Dispatcher class. Followup calls will use the cached MBeanServerConnection.
     *
     * @return MBeanServerConnection to the remote MBeanServer
     */
    private MBeanServerClient getMBeanServerClient()
    {
        if( client != null )
            return client;

        if( conn == null )
            getMBeanServerConnection();

        client = new MBeanServerClient(conn);
        return client;
    }

    /**
     * Deploys the user specified MBean on the remote MBeanServer.
     */
    public void deploy()
    {
        Logger.printlnBlue("Starting MBean deployment.");
        Logger.lineBreak();
        Logger.increaseIndent();

        String mBeanClassName = Option.require(Option.DEPLOY_BEAN_CLASS);
        ObjectName mBeanObjectName = Utils.getObjectName(Option.require(Option.DEPLOY_BEAN_NAME));

        MBeanServerClient mBeanServerClient = getMBeanServerClient();
        mBeanServerClient.deployMBean(mBeanClassName, mBeanObjectName, true);

        Logger.decreaseIndent();
    }



    public void brute() {};
    public void downloadFile() {};
    public void enumerate() {};
    public void executeCommand() {};
    public void serial() {};
    public void shell() {};
    public void tomcat() {};
    public void invokeTonkaBean() {};
    public void undeployMBean() {};
    public void uploadFile() {};

}
