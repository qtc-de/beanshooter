package de.qtc.beanshooter.networking;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.UUID;

import com.sun.net.httpserver.HttpServer;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.utils.Utils;

/**
 * The StagerServer class is used to create an HTTP listener that servers MBeans that can be
 * loaded using the getMBeansFromURL function of the MLet MBean. It exposes the MLet and the
 * JarHandler that are responsible for serving the MLet HTML and the Jar file that implements
 * the MBean to deploy.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class StagerServer
{
    private final int port;
    private final String host;
    private final boolean stagerOnly;
    private HttpServer server;

    /**
     * Initializes the StagerServer object.
     *
     * @param host address to listen on
     * @param port port to listen on
     * @param stagerOnly whether or not the server was created using the stager action
     */
    public StagerServer(String host, int port, boolean stagerOnly)
    {
        this.host = host;
        this.port = port;
        this.stagerOnly = stagerOnly;
    }

    /**
     * Returns value of the stagerOnly property.
     *
     * @return true if the StagerServer is a stagerOnly server.
     */
    public boolean isStagerOnly()
    {
        return stagerOnly;
    }

    /**
     * Startup the HTTP server and register the corresponding handlers.
     *
     * @param url url where the MBean is served
     * @param jarFile file system path to the jarFile to serve
     * @param beanClass class that is implemented by the MBean to deploy
     * @param objectName objectName of the MBean to deploy
     */
    public void start(String url, String jarFile, String beanClass, String objectName)
    {
        try {
            server = HttpServer.create(new InetSocketAddress(host, port), 0);
            Logger.printlnMixedBlue("Creating HTTP server on:", host + ":" + port);

            String jarName = UUID.randomUUID().toString().replace("-", "");

            Logger.printlnMixedBlue("Creating MLetHandler for endpoint:", "/");
            server.createContext("/", new MLetHandler(url, beanClass, jarName, objectName, this));

            Logger.printlnMixedBlue("Creating JarHandler for endpoint:", "/" + jarName);
            server.createContext("/" + jarName, new JarHandler(jarFile, this));

            server.setExecutor(null);

            Logger.printlnYellow("Starting HTTP server.");
            Logger.println("");

            server.start();

        } catch( IOException e ) {

            Throwable t = ExceptionHandler.getCause(e);

            Logger.resetIndent();
            Logger.eprintlnMixedYellow("Caught", t.getClass().getName(), "while creating the stager server.");

            if( t instanceof java.net.BindException ) {

                Logger.eprintlnMixedBlue("The endpoint", String.format("%s:%s", host, port), "is probably in use.");
                Logger.eprintlnMixedYellow("Specify", BeanshooterOption.DEPLOY_NO_STAGER.name(), "if you use an extern stager server.");;

            } else if( t instanceof java.net.SocketException && t.getMessage().contains("Permission denied") ) {

                Logger.printlnMixedBlue("You don't have sufficient permissions to bind port", String.valueOf(port), "on this host.");

            } else {
                ExceptionHandler.unknownReason(e);
            }

            ExceptionHandler.showStackTrace(e);
            Utils.exit();

        } catch( java.lang.IllegalArgumentException e ) {

            Logger.resetIndent();

            if( e.getMessage().contains("port out of range") ) {

                Logger.eprintlnMixedYellow("Caught", "IllegalArgumentException", "while creating the stager server.");
                Logger.printlnMixedBlue("The specified port", String.valueOf(port), "is out of range.");
                Logger.printlnMixedYellow("Specify a port within the range", String.format("0-%s", Short.MAX_VALUE * 2 + 1));
                ExceptionHandler.showStackTrace(e);
                Utils.exit();
            }
        }
    }

    /**
     * Stop the HTTP server.
     */
    public void stop()
    {
        server.stop(0);
    }
}
