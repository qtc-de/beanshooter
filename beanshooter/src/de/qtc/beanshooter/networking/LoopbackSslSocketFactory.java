package de.qtc.beanshooter.networking;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocketFactory;

import de.qtc.beanshooter.io.Logger;


public class LoopbackSslSocketFactory extends SSLSocketFactory {

    public static String host = "";
    public static SSLSocketFactory fac = null;
    public static boolean printInfo = true;
    public static boolean followRedirect = false;

    @Override
    public Socket createSocket(String target, int port) throws IOException {
        if(!host.equals(target)) {
            printInfos("RMI object tries to connect to different remote host: " + target);

            if( followRedirect ) {
                printInfos("\tFollowing connection to new target... ");
            } else {
                printInfos("\tRedirecting the connection back to " + host + "... ");
                target = host;
            }
            printInfos("\tThis is done for all further requests. This message is not shown again.");
            printInfo = false;
        }
        return fac.createSocket(target, port);
    }

    @Override
    public Socket createSocket(Socket arg0, String arg1, int arg2, boolean arg3) throws IOException {
        return fac.createSocket(arg0, arg1, arg2, arg3);
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return fac.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return fac.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1) throws IOException {
        return fac.createSocket(arg0, arg1);
    }

    @Override
    public Socket createSocket(String arg0, int arg1, InetAddress arg2, int arg3) throws IOException, UnknownHostException {
        return fac.createSocket(arg0, arg1, arg2, arg3);
    }

    @Override
    public Socket createSocket(InetAddress arg0, int arg1, InetAddress arg2, int arg3) throws IOException {
        return fac.createSocket(arg0, arg1, arg2, arg3);
    }

    private void printInfos(String info) {
        if( printInfo ) {
            Logger.println_bl(info);
        }
    }
}
