package eu.tneitzel.beanshooter.plugin;

import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;


/**
 * The Template class represents a template to develop beanshooter plugins.
 * It implements all the available plugin interfaces, but only uses placeholder implementations.
 * If you want to build a plugin from it, remove the interfaces and methods that you do not
 * intend to use. Other methods need to be overwritten with actual useful implementations.
 *
 * When changing the class name, make sure to also change the BeanshooterPluginClass entry within the
 * pom.xml file.
 */
public class Template implements IArgumentProvider, IAuthenticationProvider, IMBeanServerProvider, IPayloadProvider, IResponseHandler, ISocketFactoryProvider
{
    /**
     * Construct the client socket factory to use. This factory is used to create sockets
     * for direct RMI communication (e.g. when connecting to the RMI registry).
     *
     * @param host  remote host
     * @param port  remote port
     * @return RMIClientSocketFactory to use
     */
    public RMIClientSocketFactory getClientRMISocketFactory(String host, int port)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Construct the RMI socket factory to use. This factory is used for implicit RMI
     * connections, e.g. when calling a method on a previously obtained remote object.
     *
     * @param host  remote host
     * @param port  remote port
     * @return RMISocketFactory to use
     */
    public RMISocketFactory getDefaultRMISocketFactory(String host, int port)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Return the SSL socket factory that should be used for non RMI based TLS connections.
     * This is e.g. use for the JMXMP provider.
     *
     * @param host  remote host
     * @param port  remote port
     * @return SocketFactory to use for the connection
     */
    public String getSSLSocketFactory(String host, int port)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Return the SSL socket factory class that should be used for implicit RMI connections.
     *
     * @param host  remote host
     * @param port  remote port
     * @return name of the SSL socket factory class to use for SSL connections.
     */
    public String getDefaultSSLSocketFactory(String host, int port)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Handle the response of an MBean call.
     *
     * @param responseObject the object that was returned by the server.
     */
    public void handleResponse(Object responseObject)
    {
        // TODO Override with something useful or remove
    }

    /**
     * Provide an argument array for MBean calls.
     *
     * @param args the arguments specified on the command line
     * @return argument array for a remote method call
     */
    public Object[] getArgumentArray(String[] args)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Construct an array of type names describing the argument types of
     * an MBean call.
     *
     * @param signature method signature of the MBean method called
     * @return array of class names describing the argument types
     */
    public String[] getArgumentTypes(String signature)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Construct an array of type names describing the argument types of
     * an MBean call.
     *
     * @param signature method signature of the MBean method called
     * @param includeName whether to include the method name
     * @return array of class names describing the argument types
     */
    public String[] getArgumentTypes(String signature, boolean includeName)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Obtain the method name from a function singature.
     *
     * @param signature method signature supplied by the user
     * @return the method name
     */
    public String getMethodName(String signature)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Creates an object from an input string. This method is used during
     * the model action, to create an object based on the user input.
     *
     * @param str argument string supplied by the user
     * @return Object constructed from the argument string
     */
    public Object strToObj(String str)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Provide a payload object for deserialization attacks.
     *
     * @param action the current RMG action that requested the gadget
     * @param name the name of the gadget being requested
     * @param args the arguments provided for the gadget
     * @return a payload object to use for deserialization attacks
     */
    public Object getPayloadObject(Operation action, String name, String args)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Provide a custom Map object for JMX authentication.
     *
     * @param username user specified username
     * @param password user specified password
     * @return Map to use for JMX authentication
     */
    public Map<String,Object> getEnv(String username, String password)
    {
        // TODO Override with something useful or remove
        return null;
    }

    /**
     * Provide a custom method for obtaining an MBeanServerConnection.
     *
     * @param host user specified host to connect to
     * @param port user specified port to connect to
     * @param env Map containing authentication information
     * @return MBeanServerConnection for MBeanCalls
     */
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env)
    {
        // TODO Override with something useful or remove
        return null;
    }
}
