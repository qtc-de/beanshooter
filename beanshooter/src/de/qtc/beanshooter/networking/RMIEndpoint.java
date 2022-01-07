package de.qtc.beanshooter.networking;

import java.rmi.server.ObjID;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RemoteRef;

import de.qtc.beanshooter.plugin.PluginSystem;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.Endpoint;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

/**
 * The RMIEndpoint class represents an RMI endpoint on a remote server. RMIEndpoint can be extended
 * by RMIRegistryEndpoint, which supports some more registry related functionalities.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class RMIEndpoint {

    public int port;
    public String host;

    protected RMIClientSocketFactory csf;

    /**
     * Creates a new RMIEndpoint instance and configures the corresponding client side socket
     * factory according to the options specified on the command line.
     *
     * @param host Remote host where the RMIEndpoint belongs to
     * @param port Remote port where the RMIEndpoint belongs to
     */
    public RMIEndpoint(String host, int port)
    {
         this.host = host;
         this.port = port;
         this.csf = PluginSystem.getClientSocketFactory();
    }

    /**
     * Creates a new RMIEndpoint instance and allows the user to specify a client side
     * socket factory.
     *
     * @param host Remote host where the RMIEndpoint belongs to
     * @param port Remote port where the RMIEndpoint belongs to
     * @param csf Socket factory to use for connection attempts
     */
    public RMIEndpoint(String host, int port, RMIClientSocketFactory csf)
    {
         this.host = host;
         this.port = port;
         this.csf = csf;
    }

    /**
     * Constructs a RemoteRef by using the endpoint information (host, port, csf) and the
     * specified objID.
     *
     * @param objID identifies the targeted remote object on the server side
     * @return newly constructed RemoteRef
     */
    public RemoteRef getRemoteRef(ObjID objID)
    {
        Endpoint endpoint = new TCPEndpoint(host, port, csf, null);
        return new UnicastRef(new LiveRef(objID, endpoint, false));
    }
}