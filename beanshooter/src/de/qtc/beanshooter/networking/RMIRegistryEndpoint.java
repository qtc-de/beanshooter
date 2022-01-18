package de.qtc.beanshooter.networking;

import java.io.IOException;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;
import java.rmi.server.RMISocketFactory;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.PluginSystem;
import de.qtc.beanshooter.utils.Utils;

/**
 * The RMIRegistryEndpoint represents an RMI Registry endpoint on the remote server. The class can be used
 * to perform some high level RMI registry access like list and lookup operations.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RMIRegistryEndpoint extends RMIEndpoint {

    private Registry rmiRegistry;
    private Map<String,Remote> remoteObjectCache;
    
    private static boolean setupComplete = false;

    /**
     * The main purpose of this constructor function is to setup the different socket factories.
     * During the initial connect to the registry, a socket factory can be specified manually and
     * will be used. This is done by the RMIEndpoint class already. However, for the communication
     * to looked up remote objects, the socket factory that was configured on the server side will
     * be used.
     *
     * For most cases this will be either RMISocketFactory or SslRMIClientSocketFactory. To implement
     * stuff like automatic redirection, we need to overwrite the default implementations of these
     * classes. This is done by this constructor.
     *
     * @param host RMI registry host
     * @param port RMI registry port
     */
    public RMIRegistryEndpoint(String host, int port)
    {
        super(host, port);

        this.remoteObjectCache = new HashMap<String,Remote>();
        SocketFactorySetup(host, port);

        try {
            this.rmiRegistry = LocateRegistry.getRegistry(host, port, csf);

        } catch( RemoteException e ) {
            ExceptionHandler.internalError("RMIRegistryEndpoint.locateRegistry", "Caught unexpected RemoteException.");
            ExceptionHandler.stackTrace(e);
            Utils.exit();
        }
    }

    /**
     * Alternative constructor that creates the RMIRegistryEndpoint from an already existing RMIEndpoint.
     *
     * @param rmi RMIEndpoint
     */
    public RMIRegistryEndpoint(RMIEndpoint rmi)
    {
        this(rmi.host, rmi.port);
    }
    
    private static void SocketFactorySetup(String host, int port)
    {
        if( setupComplete )
        	return;
        
	    try {
	        RMISocketFactory.setSocketFactory(PluginSystem.getDefaultRMISocketFactory(host, port));
	
	    } catch (IOException e) {
	        Logger.eprintlnMixedBlue("Unable to set custom", "RMISocketFactory.", "Host redirection will probably not work.");
	        ExceptionHandler.showStackTrace(e);
	        Logger.eprintln("");
	    }
	
	    java.security.Security.setProperty("ssl.SocketFactory.provider", PluginSystem.getDefaultSSLSocketFactoryClass(host, port));
	    setupComplete = true;
    }

    /**
     * If a bound name was specified on the command line, return this bound name immediately. Otherwise,
     * obtain a list of bound names from the RMI registry. This is basically a wrapper around the list
     * function of the RMI registry, but has error handling implemented.
     *
     * @return String array of available bound names.
     */
    public String[] getBoundNames()
    {
        if( BeanshooterOption.TARGET_BOUND_NAME.notNull() )
            return new String[] { BeanshooterOption.TARGET_BOUND_NAME.getValue() };

        String[] boundNames = null;

        try {
            boundNames = rmiRegistry.list();

        } catch( java.rmi.ConnectIOException e ) {
            ExceptionHandler.connectIOException(e, "list");

        } catch( java.rmi.ConnectException e ) {
            ExceptionHandler.connectException(e, "list");

        } catch( java.rmi.UnknownHostException e ) {
            ExceptionHandler.unknownHost(e, host, true);

        } catch( java.rmi.NoSuchObjectException e ) {
            Logger.printlnMixedYellow("Caught", "NoSuchObjectException", "during list operation.");
            Logger.printlnMixedBlue("The specified endpoint",  "is not", "an RMI registry.");
            Utils.exit();

        } catch( Exception e ) {
            ExceptionHandler.unexpectedException(e, "list", "call", true);
        }

        return boundNames;
    }

    /**
     * Performs the RMI registries lookup operation to obtain a remote reference for the specified
     * bound names.
     *
     * @param boundNames list of bound names to determine the classes from
     * @return List of remote objects
     * @throws Reflection related exceptions. RMI related once are caught by the other lookup function.
     */
    public Remote[] lookup(String[] boundNames)
    {
        List<Remote> remoteObjects = new ArrayList<Remote>();

        for(String boundName : boundNames) {

            try {
                remoteObjects.add(lookup(boundName));

            } catch( ClassNotFoundException e ) {}
        }

        return remoteObjects.toArray(new Remote[0]);
    }

    /**
     * Just a wrapper around the lookup method of the RMI registry. Performs exception handling
     * and caches remote objects that have already been looked up.
     *
     * @param boundName name to lookup within the registry
     * @return Remote representing the requested remote object
     * @throws ClassNotFoundException
     */
    public Remote lookup(String boundName) throws ClassNotFoundException
    {
        Remote remoteObject = remoteObjectCache.get(boundName);

        if( remoteObject == null ) {

            try {
                remoteObject = rmiRegistry.lookup(boundName);
                remoteObjectCache.put(boundName, remoteObject);

            } catch( java.rmi.ConnectIOException e ) {
                ExceptionHandler.connectIOException(e, "lookup");

            } catch( java.rmi.ConnectException e ) {
                ExceptionHandler.connectException(e, "lookup");

            } catch( java.rmi.UnknownHostException e ) {
                ExceptionHandler.unknownHost(e, host, true);

            } catch( java.rmi.NoSuchObjectException e ) {
                ExceptionHandler.noSuchObjectException(e, "registry", true);

            } catch( java.rmi.NotBoundException e ) {
                ExceptionHandler.notBoundException(e, boundName);

            } catch( Exception e ) {

                Throwable cause = ExceptionHandler.getCause(e);

                if( cause instanceof ClassNotFoundException )
                    throw (ClassNotFoundException)cause;

                else
                    ExceptionHandler.unexpectedException(e, "lookup", "call", true);
            }
        }

        return remoteObject;
    }

    /**
     * Return the Remote for the specified bound name from cache or null if it is not available.
     *
     * @param boundName name to lookup within the cache
     * @return Remote representing the requested remote object
     */
    public Remote getFromCache(String boundName)
    {
        return remoteObjectCache.get(boundName);
    }
}
