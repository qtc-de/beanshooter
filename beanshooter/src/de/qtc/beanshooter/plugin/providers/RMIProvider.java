package de.qtc.beanshooter.plugin.providers;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.rmi.Remote;
import java.rmi.RemoteException;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.security.cert.CertPathValidatorException;
import java.util.HashMap;
import java.util.Map;

import javax.management.MBeanServerConnection;
import javax.management.remote.rmi.RMIConnection;
import javax.management.remote.rmi.RMIConnector;
import javax.management.remote.rmi.RMIServer;
import javax.security.auth.callback.UnsupportedCallbackException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ApacheKarafException;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.GlassFishException;
import de.qtc.beanshooter.exceptions.InvalidLoginClassException;
import de.qtc.beanshooter.exceptions.LoginClassCastException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.networking.RMIEndpoint;
import de.qtc.beanshooter.networking.RMIRegistryEndpoint;
import de.qtc.beanshooter.operation.BeanshooterOperation;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.IMBeanServerProvider;
import de.qtc.beanshooter.utils.Utils;

/**
 * The RMIProvider provides an MBeanServerConnection by using regular Java RMI calls.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class RMIProvider implements IMBeanServerProvider
{
    /**
     * Obtain an MBeanServerConnection from the specified endpoint. How the endpoint is obtained depends
     * on other command line arguments.
     * @throws AuthenticationException
     */
    @SuppressWarnings("resource")
    @Override
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env) throws AuthenticationException
    {
        RMIRegistryEndpoint regEndpoint = new RMIRegistryEndpoint(host, port);

        RMIServer rmiServer = null;
        RMIConnector rmiConnector = null;
        MBeanServerConnection connection = null;

        if (BeanshooterOption.TARGET_OBJID_CONNECTION.notNull())
        {
            ObjID objID = Utils.parseObjID(BeanshooterOption.TARGET_OBJID_CONNECTION.getValue());
            RMIConnection conn = getRMIConnectionByObjID(regEndpoint, objID);

            rmiServer = new FakeRMIServer(conn);
        }

        else
        {
            rmiServer = getRMIServer(regEndpoint);
        }

        rmiConnector = new RMIConnector(rmiServer, env);

        try
        {
            rmiConnector.connect();
            connection = rmiConnector.getMBeanServerConnection();
        }

        catch (IOException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof java.io.InvalidClassException)
                throw new InvalidLoginClassException(e);

            else if (t instanceof java.lang.ClassNotFoundException)
                throw new InvalidLoginClassException(e);

            else if (t instanceof java.rmi.ConnectIOException)
                ExceptionHandler.connectIOException(e, "newclient");

            else if (t instanceof java.io.NotSerializableException && t.getMessage().contains("PrincipalCallback"))
                throw new GlassFishException(e);

            else if (t instanceof UnsupportedCallbackException)
                ExceptionHandler.unsupportedCallback((Exception)t);

            Logger.resetIndent();
            Logger.eprintlnMixedYellow("Caught", t.getClass().getName(), "while invoking the newClient method.");

            if (t instanceof java.rmi.NoSuchObjectException)
                Logger.eprintlnMixedBlue("You probably specified an", "ObjID value", "that does not exist on the server.");

            else if (t instanceof java.net.ConnectException)
            {
                if (t.getMessage().contains("Connection refused"))
                {
                    Logger.eprintlnMixedBlue("The JMX remote object", "refused", "the connection.");
                }

                else if (t.getMessage().contains("Network is unreachable"))
                {
                    Logger.eprintlnMixedBlue("The JMX remote object is", "unreachable.");

                }

                else
                {
                    ExceptionHandler.unknownReason(e);
                }

                if (BeanshooterOption.TARGET_OBJID_CONNECTION.isNull())
                    Logger.eprintlnMixedYellow("The JMX", "bound name", "within the RMI registry is probably pointing to an invalid server.");
            }

            else if (t instanceof java.io.EOFException || t instanceof java.net.SocketException)
            {
                Logger.eprintln("The JMX server closed the connection. This usually indicates a networking problem.");
            }

            else if (ArgumentHandler.getInstance().getAction() == BeanshooterOperation.SERIAL && BeanshooterOption.SERIAL_PREAUTH.getBool())
            {
                Logger.eprintlnMixedBlue("This exception could be caused by the selected gadget and the deserialization attack may", "worked anyway.");

                if (!BeanshooterOption.GLOBAL_STACK_TRACE.getBool())
                    Logger.eprintlnMixedYellow("If it did not work you may want to rerun with the", "--stack-trace", "option to further investigate.");
            }

            else if (t instanceof CertPathValidatorException)
            {
                Logger.eprintlnMixedBlue("The server probably uses TLS settings that are", "incompatible", "with your current security settings.");
                Logger.eprintlnMixedYellow("You may try to edit your", "java.security", "policy file to overcome the issue.");
                Utils.exit(e);
            }

            else
            {
                ExceptionHandler.unknownReason(e);
            }

            Utils.exit(e);
        }

        catch (SecurityException e)
        {
            ExceptionHandler.handleSecurityException(e);
        }

        catch (java.lang.IllegalArgumentException e)
        {
            if (e.getMessage().contains("Expected String[2]"))
                throw new ApacheKarafException(e);

            throw e;
        }

        catch (Exception e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            if (t instanceof ClassCastException)
                throw new LoginClassCastException(e);

            throw e;
        }

        return connection;
    }

    /**
     * Obtains an RMIConnection object via ObjID.
     *
     * @param objID ObjID value of the remote object to connect to
     * @return RMIConnection to the remote MBeanServer
     */
    private RMIConnection getRMIConnectionByObjID(RMIEndpoint endpoint, ObjID objID)
    {
        RemoteRef ref = endpoint.getRemoteRef(objID);
        RemoteObjectInvocationHandler handler = new RemoteObjectInvocationHandler(ref);

        return (RMIConnection)Proxy.newProxyInstance(RMIProvider.class.getClassLoader(), new Class[] { RMIConnection.class }, handler);
    }

    /**
     * Obtains an RMIServer object either via lookup on an RMI registry or via a directly specified
     * ObjID value.
     *
     * @return RMIServer object
     */
    public RMIServer getRMIServer(RMIRegistryEndpoint regEndpoint)
    {
        if( BeanshooterOption.TARGET_OBJID_SERVER.notNull() )
        {
            ObjID objID = Utils.parseObjID(BeanshooterOption.TARGET_OBJID_SERVER.getValue());
            return getRMIServerByObjID(regEndpoint, objID);
        }

        return getRMIServerByLookup(regEndpoint);
    }

    /**
     * Obtains an RMIServer object via a directly specified ObjID value.
     *
     * @param objID ObjID value of the targeted RMIServer
     * @return RMIServer object
     */
    private RMIServer getRMIServerByObjID(RMIEndpoint endpoint, ObjID objID)
    {
        RemoteRef ref = endpoint.getRemoteRef(objID);
        RemoteObjectInvocationHandler handler = new RemoteObjectInvocationHandler(ref);

        return (RMIServer)Proxy.newProxyInstance(RMIProvider.class.getClassLoader(), new Class[] { RMIServer.class }, handler);
    }

    /**
     * Obtains an RMIServer object via an RMI registry lookup.
     *
     * @param boundName boundName to lookup on the RMI registry
     * @return RMIServer object
     */
    private RMIServer getRMIServerByLookup(RMIRegistryEndpoint regEndpoint, String boundName)
    {
        RMIServer returnValue = null;

        try
        {
            returnValue = (RMIServer)regEndpoint.lookup(boundName);
        }

        catch (ClassNotFoundException e)
        {
            ExceptionHandler.lookupClassNotFoundException(e, e.getMessage());
        }

        catch (ClassCastException e)
        {
            Logger.printlnMixedYellow("Unable to cast remote object to", "RMIServer", "class.");
            Logger.printlnMixedBlue("You probbably specified a bound name that does not implement the", "RMIServer", "interface.");
            Utils.exit(e);
        }

        return returnValue;
    }

    /**
     * Obtains an RMIServer object via an RMI registry lookup.

     * @return RMIServer object
     */
    private RMIServer getRMIServerByLookup(RMIRegistryEndpoint regEndpoint)
    {
        if( BeanshooterOption.TARGET_BOUND_NAME.notNull() )
            return getRMIServerByLookup(regEndpoint, BeanshooterOption.TARGET_BOUND_NAME.getValue());

        Map<String, Remote> mappings = new HashMap<String, Remote>();
        String[] boundNames = regEndpoint.getBoundNames();

        for (String boundName : boundNames)
        {
            try
            {
                Remote remote = regEndpoint.lookup(boundName);
                mappings.put(boundName, remote);
            }

            catch (ClassNotFoundException e) {}
        }

        Map<String,Remote> jmxMap = Utils.filterJmxEndpoints(mappings);
        int jmxEndpoints = jmxMap.size();

        if( jmxEndpoints == 0 )
        {
            Logger.printlnMixedYellow("The specified RMI registry", "does not", "contain any JMX objects.");
            Utils.exit();
        }

        String selected = (String) jmxMap.keySet().toArray()[0];
        Remote selectedRemote = jmxMap.get(selected);

        if (jmxEndpoints > 1)
        {
            Logger.printlnMixedYellow("RMI registry contains", "more than one", "JMX instance.");
            Logger.printlnMixedBlue("The bound name", selected, "is used for the operation.");
            Logger.printlnMixedYellow("Use the", "--bound-name", "option to select a different one.");
            Logger.lineBreak();
        }

        return (RMIServer)selectedRemote;
    }

    /**
     * The FakeRMIServer class is used to wrap an RMIConnection into an MBeanServerConnection object.
     * Since there are no easy to use API functions to achieve this, we create a custom RMIServer object
     * that returns the RMIConnection object on login. When using the default JMX methods on this RMIServer
     * object, the returned RMIConnection gets automatically wrapped into an MBeanServerConnection.
     *
     * @author Tobias Neitzel (@qtc_de)
     */
    private class FakeRMIServer implements RMIServer {

        private final RMIConnection conn;

        /**
         * Initialize the FakeRMIServer with the RMIConnection object that should be returned on login.
         *
         * @param conn RMIConnection object to return on login
         */
        public FakeRMIServer(RMIConnection conn)
        {
            this.conn = conn;
        }

        /**
         * Not required but defined in RMIServer.
         */
        @Override
        public String getVersion() throws RemoteException
        {
            return "1.0";
        }

        /**
         * Just always return the stored RMIConnection object.
         */
        @Override
        public RMIConnection newClient(Object credentials) throws IOException
        {
            return conn;
        }
    }
}
