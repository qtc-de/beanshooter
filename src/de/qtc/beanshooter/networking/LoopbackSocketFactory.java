package de.qtc.beanshooter.networking;

import java.net.Socket;
import java.io.IOException;
import java.net.ServerSocket;
import java.rmi.server.RMISocketFactory;

import de.qtc.beanshooter.io.Logger;

public class LoopbackSocketFactory extends RMISocketFactory {

    private String host;
    private RMISocketFactory fac;
    private boolean printInfo = true;
    private boolean followRedirect = false;

    public LoopbackSocketFactory(String host, RMISocketFactory fac, boolean followRedirect) {
        this.host = host;
        this.fac = fac;
        this.followRedirect= followRedirect;
    }

    public ServerSocket createServerSocket(int port) throws IOException {
        return fac.createServerSocket(port);
    }

    public Socket createSocket(String host, int port) throws IOException {
        if(!this.host.equals(host)) {
            printInfos("RMI object tries to connect to different remote host: " + host);

            if( this.followRedirect ) {
                printInfos("\tFollowing connection to new target... ");
            } else {
                printInfos("\tRedirecting the connection back to " + this.host + "... ");
                host = this.host;
            }
            printInfos("\tThis is done for all further requests. This message is not shown again.");
            this.printInfo = false;
        }
        return fac.createSocket(host, port);
    }

    private void printInfos(String info) {
        if( this.printInfo ) {
            Logger.println_bl(info);
        }
    }
}
