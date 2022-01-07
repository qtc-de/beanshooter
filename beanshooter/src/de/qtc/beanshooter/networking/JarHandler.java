package de.qtc.beanshooter.networking;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.file.Files;

import org.apache.commons.io.IOUtils;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.utils.Utils;

/**
 * The JarHandler class is responsible for serving the Jar file during an MBean
 * deployment process. Furhermore, it exposes an export method that can be used
 * to export the Jar to the file system.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class JarHandler implements HttpHandler {

    private final String digest;
    private final byte[] jarContent;
    private final boolean stagerOnly;
    private final StagerServer parent;

    /**
     * Initializes the JarHandler object.
     *
     * @param filename the filename of the Jar file to serve
     * @param stagerOnly whether or not the handler is created through the stager action
     * @param parent the parent StagerServer where the handler is used
     * @throws IOException
     */
    public JarHandler(String filename, boolean stagerOnly, StagerServer parent) throws IOException
    {
        this.parent = parent;
        this.stagerOnly = stagerOnly;
        this.jarContent = getJar(filename);
        this.digest = Utils.md5sum(jarContent);
    }

    /**
     * Loads the specified Jar file into memory. The method first checks whether the specified
     * Jar file exists on the file system. If this is not the case, the filename is interpreted
     * as name of a Jar file within the beanshooter Jar file. This is there the tonka bean is
     * stored.
     *
     * @param filename path of the Jar file to serve
     * @return content of the Jar file
     * @throws IOException
     */
    private byte[] getJar(String filename) throws IOException
    {
        File file = new File(filename);

        if( file.exists() )
            return Files.readAllBytes(file.toPath());

        InputStream stream = this.getClass().getResourceAsStream("/" + filename);
        byte[] content = IOUtils.toByteArray(stream);

        if( content.length == 0 ) {

            Logger.resetIndent();
            Logger.lineBreak();
            Logger.eprintln("Error while creating HTTP JarHandler.");
            Logger.eprintlnMixedYellow("Unable to find jar file with path:", filename);
            Utils.exit();
        }

        return content;
    }

    /**
     * Exports the Jar file to the file system. This is mainly used to export the tonka bean
     * Jar, that is contained within the beanshooter Jar.
     *
     * @param filename path to export to
     * @throws IOException
     */
    public void export(String filename) throws IOException
    {
        Logger.printlnMixedBlue("Exporting MBean jar file:", filename);

        File file = new File(filename);
        Files.write(file.toPath(), jarContent);
    }

    /**
     * Handles an incoming HTTP request to the handler path. Returns the previously loaded Jar
     * file to the client. If the StagerServer was created using the stager action, the StagerServer
     * is kept alive after an incoming call. If the StagerServer was created using the deploy action,
     * it is stopped after serving the Jar.
     */
    public void handle(HttpExchange t) throws IOException
    {
        if( stagerOnly ) {
            System.out.println("");
            Logger.lineBreak();
        }

        String requestURL = t.getRequestURI().toString();
        InetSocketAddress requestee = t.getRemoteAddress();

        Logger.printlnMixedYellow("Incoming request from:", requestee.getHostName());
        Logger.printlnMixedYellow("Requested resource:", requestURL);

        Logger.printlnMixedBlue("Sending jar file with md5sum:", digest);

        t.sendResponseHeaders(200, jarContent.length);
        OutputStream os = t.getResponseBody();

        os.write(jarContent, 0, jarContent.length);
        os.close();

        Logger.lineBreak();

        if( stagerOnly )
            Logger.printlnBlue("Press Enter to stop listening...");

        else
            parent.stop();
    }
}
