package de.qtc.beanshooter.plugin;

import java.io.File;
import java.io.FileInputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;
import java.util.Map;
import java.util.jar.JarInputStream;
import java.util.jar.Manifest;

import javax.management.MBeanServerConnection;
import javax.net.SocketFactory;

import org.jolokia.client.exception.J4pRemoteException;

import de.qtc.beanshooter.cli.Operation;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.MalformedPluginException;
import de.qtc.beanshooter.exceptions.PluginException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.providers.ArgumentProvider;
import de.qtc.beanshooter.plugin.providers.AuthenticationProvider;
import de.qtc.beanshooter.plugin.providers.JMXMPProvider;
import de.qtc.beanshooter.plugin.providers.JNDIProvider;
import de.qtc.beanshooter.plugin.providers.JolokiaProvider;
import de.qtc.beanshooter.plugin.providers.RMIProvider;
import de.qtc.beanshooter.plugin.providers.ResponseHandlerProvider;
import de.qtc.beanshooter.plugin.providers.SocketFactoryProvider;
import de.qtc.beanshooter.plugin.providers.YsoSerialProvider;
import de.qtc.beanshooter.utils.Utils;

/**
 * The PluginSystem class allows beanshooter to be extended by user defined classes. Plugins can be
 * loaded by using the --plugin option on the command line. Plugins need to overwrite at least one of
 * the provided plugin interfaces: IMBeanServerProvider or ISocketFactoryProvider.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class PluginSystem {

    private static IMBeanServerProvider mBeanServerProvider;
    private static ISocketFactoryProvider socketFactoryProvider;
    private static IPayloadProvider payloadProvider;
    private static IArgumentProvider argumentProvider;
    private static IResponseHandler responseHandler;
    private static IAuthenticationProvider authenticationProvider;

    private static final String manifestAttribute = "BeanshooterPluginClass";

    /**
     * Initializes the plugin system. This basically instantiates the default plugins and assigns them
     * to the plugin system. If a plugin path was specified, the plugin is checked and the default plugins
     * are probably replaced.
     *
     * @param pluginPath user specified plugin path or null
     */
    public static void init(String pluginPath)
    {
        mBeanServerProvider = selectProvider();
        socketFactoryProvider = new SocketFactoryProvider();
        payloadProvider = new YsoSerialProvider();
        argumentProvider = new ArgumentProvider();
        responseHandler = new ResponseHandlerProvider();
        authenticationProvider = new AuthenticationProvider();

        if(pluginPath != null)
            loadPlugin(pluginPath);
    }

    /**
     * Attempts to load the plugin from the user specified plugin path. Plugins are expected to be JAR files that
     * contain the 'BeanshooterPluginClass' attribute within their manifest. The corresponding attribute needs to
     * contain the class name of the class that actually implements the plugin.
     *
     * beanshooter attempts to load the specified class using an URLClassLoader. It then attempts to identify which
     * interfaces are implemented by the class. E.g. if the class implements the IMBeanServerProvider interface, the
     * default mBeanServerProvider of the PluginSystem class gets overwritten with the class from the plugin.
     *
     * @param pluginPath file system path to the plugin to load
     */
    @SuppressWarnings("deprecation")
    private static void loadPlugin(String pluginPath)
    {
        boolean inUse = false;
        Object pluginInstance = null;
        String pluginClassName = null;
        JarInputStream jarStream = null;
        File pluginFile = new File(pluginPath);

        if(!pluginFile.exists()) {
            Logger.eprintlnMixedYellow("Specified plugin path", pluginPath, "does not exist.");
            Utils.exit();
        }

        try {
            jarStream = new JarInputStream(new FileInputStream(pluginFile));
            Manifest mf = jarStream.getManifest();
            pluginClassName = mf.getMainAttributes().getValue(manifestAttribute);
            jarStream.close();

            if(pluginClassName == null)
                throw new MalformedPluginException();

        } catch(Exception e) {
            Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), "while reading the Manifest of the specified plugin.");
            Logger.eprintlnMixedBlue("Plugins need to be valid JAR files that contain the", manifestAttribute, "attribute.");
            Utils.exit();
        }

        try {
            URLClassLoader ucl = new URLClassLoader(new URL[] {pluginFile.toURI().toURL()});
            Class<?> pluginClass = Class.forName(pluginClassName, true, ucl);
            pluginInstance = pluginClass.newInstance();

        } catch(Exception e) {
            Logger.eprintMixedYellow("Caught", e.getClass().getName(), "while reading plugin file ");
            Logger.printlnPlainBlue(pluginPath);
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }

        if(pluginInstance instanceof IMBeanServerProvider) {
            mBeanServerProvider = (IMBeanServerProvider)pluginInstance;
            inUse = true;

        } if(pluginInstance instanceof ISocketFactoryProvider) {
            socketFactoryProvider = (ISocketFactoryProvider)pluginInstance;
            inUse = true;

        } if(pluginInstance instanceof IPayloadProvider) {
            payloadProvider = (IPayloadProvider)pluginInstance;
            inUse = true;

        } if(pluginInstance instanceof IArgumentProvider) {
            argumentProvider = (IArgumentProvider)pluginInstance;
            inUse = true;

        } if(pluginInstance instanceof IResponseHandler) {
            responseHandler = (IResponseHandler)pluginInstance;
            inUse = true;

        } if(pluginInstance instanceof IAuthenticationProvider) {
            authenticationProvider = (IAuthenticationProvider)pluginInstance;
            inUse = true;
        }

        if(!inUse) {
            Logger.eprintMixedBlue("Plugin", pluginPath, "was successfully loaded, but is ");
            Logger.eprintlnPlainYellow("not in use.");
            Logger.eprintln("Plugins should implement at least one of the available plugin interfaces.");
        }
    }

    /**
     * Returns the IMBeanServerProvider according to the specified command line arguments.
     *
     * @return IMBeanServerProvider according to the specified command lien arguments.
     */
    private static IMBeanServerProvider selectProvider()
    {
        if (BeanshooterOption.CONN_JMXMP.getBool())
            return new JMXMPProvider();

        if (BeanshooterOption.CONN_JNDI.notNull())
            return new JNDIProvider();

        if (BeanshooterOption.CONN_JOLOKIA.getBool())
            return new JolokiaProvider();

        return new RMIProvider();
    }

    /**
     * Attempt to obtain an MBeanServerConnection to the specified remote MBeanServer. Authentication related
     * exceptions are handled automatically. If this is not desired, the getMBeanServerConnectionUnmanaged function
     * should be used instead.
     *
     * @param host target host specified on the command line
     * @param port target port specified on the command line
     * @param env JMX environment to use for the call
     * @return MBeanServerConnection to the remote MBeanServer
     */
    public static MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env)
    {
        MBeanServerConnection conn = null;

        try
        {
            conn = mBeanServerProvider.getMBeanServerConnection(host, port, env);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        catch (J4pRemoteException e)
        {
            ExceptionHandler.handleJ4pRemoteException(e, "while connecting to the Jolokia endpoint.");
        }

        catch (AuthenticationException e)
        {
            ExceptionHandler.handleAuthenticationException(e);
            Utils.exit();
        }

        return conn;
    }

    /**
     * Depending on the beanshooter action specified on the command line, the corresponding operation may wants
     * automatic exception handling or not. Most operations should use the managed version of getMbeanServerConnection,
     * as it handles authentication related errors automatically. However, operations that need to obtain the exact reason
     * for an authentication error can call the unmanaged version and handle the error themselves.
     *
     * @param host    target host specified on the command line
     * @param port    target port specified on the command line
     * @param env    JMX environment to use for the connection attempt
     * @return MBeanServerConnection to the specified remote MBeanServer
     * @throws AuthenticationException
     */
    public static MBeanServerConnection getMBeanServerConnectionUmanaged(String host, int port, Map<String,Object> env) throws AuthenticationException, J4pRemoteException
    {
        MBeanServerConnection connection = null;

        try
        {
            connection = mBeanServerProvider.getMBeanServerConnection(host, port, env);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return connection;
    }

    /**
     * Returns the RMIClientSocketFactory that is used for RMI connections. The factory returned by this function
     * is used for all direct RMI calls. So e.g. if you call the registry or another RMI endpoint directly. If you
     * first lookup a bound name and use the obtained reference to make calls on the object, another factory is used
     * (check the getDefaultClientSocketFactory function for more details).
     *
     * @param host target host specified on the command line
     * @param port target port specified on the command line
     * @return RMIClientSocketFactory that is used for direct RMI calls
     */
    public static RMIClientSocketFactory getRMIClientSocketFactory(String host, int port)
    {
        RMIClientSocketFactory facs = null;

        try
        {
            facs = socketFactoryProvider.getRMIClientSocketFactory(host, port);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return facs;
    }

    /**
     * Returns the RMISocketFactory that is used for all RMI connections that use the default RMISocketFactory. The
     * factory returned by this function is used when you perform RMI actions on a remote object reference that was
     * obtained from the RMI registry and the RMI server did not assign a custom socket factory to the object.
     *
     * @param host target host specified on the command line
     * @param port target port specified on the command line
     * @return RMISocketFactory that is used for "after lookup" RMI calls
     */
    public static RMISocketFactory getDefaultRMISocketFactory(String host, int port)
    {
        RMISocketFactory facs = null;

        try
        {
            facs = socketFactoryProvider.getDefaultRMISocketFactory(host, port);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return facs;
    }

    /**
     * Java RMI also contains a default implementation for SSL protected RMI communication. If the server uses the
     * corresponding SocketFactory on the server side, the RMI client does too and the only way to overwrite the default
     * SSLSocketFactory is by setting a Java property. Therefore, this function should return the name of a class that
     * you want to use as your default SSLSocketFactory. Notice that the factory needs to be available on the class path
     * and it is not sufficient to define it within the plugin.
     *
     * @param host target host specified on the command line
     * @param port target port specified on the command line
     * @return String that indicates the desired SSLSocketFactories class name
     */
    public static String getDefaultSSLSocketFactoryClass(String host, int port)
    {
        String cls = null;

        try
        {
            cls = socketFactoryProvider.getDefaultSSLSocketFactoryClass(host, port);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return cls;
    }

    /**
     * Return the SocketFactory that should be used for non RMI based TLS protected connections. This is e.g.
     * required for JMXMP connections.
     *
     * @param host target host specified on the command line
     * @param port target port specified on the command line
     * @return SocketFactory for TLS protected non RMI based connections
     */
    public static SocketFactory getSSLSocketFactory(String host, int port)
    {
        SocketFactory facs = null;

        try
        {
            facs = socketFactoryProvider.getSSLSocketFactory(host, port);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return facs;
    }

    /**
     * Return a deserialization gadget that matches the command line specified arguments.
     *
     * @param op operation that requested the gadget
     * @param gadgetName name of the gadget
     * @param gadgetCmd gadget command
     * @return deserialization gadget
     */
    public static Object getPayloadObject(Operation op, String gadgetName, String gadgetCmd)
    {
        Object payload = null;

        try
        {
            payload = payloadProvider.getPayloadObject(op, gadgetName, gadgetCmd);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return payload;
    }

    /**
     * Returns the currently configured MBeanServerProvider class that implements the
     * IMBeanServerProvider interface.
     *
     * @return Configured MBeanServerProvider
     */
    public static IMBeanServerProvider getMBeanServerProvider()
    {
        return mBeanServerProvider;
    }

    /**
     * Pass the user supplied argumentArray to the ArgumentProvider and return the resulting
     * object array.
     *
     * @param argumentArray user supplied argument array
     * @return Object array parsed from the string
     */
    public static Object[] getArgumentArray(String[] argumentArray)
    {
        Object[] args = null;

        try
        {
            args = argumentProvider.getArgumentArray(argumentArray);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return args;
    }

    /**
     * Create an Object from a Java expression.
     *
     * @param str  Java expression. Class names need to be specified full qualified
     * @return Object created from the Java expression
     */
    public static Object strToObj(String str)
    {
        Object args = null;

        try
        {
            args = argumentProvider.strToObj(str);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return args;
    }

    /**
     * Pass the user supplied method signature to the ArgumentProvider and return the resulting
     * string array of parameter types.
     *
     * @param signature user supplied method signature
     * @return String array containing the parsed parameter type names
     */
    public static String[] getArgumentTypes(String signature)
    {
        String[] types = null;

        try
        {
            types = argumentProvider.getArgumentTypes(signature);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return types;
    }

    /**
     * Pass the user supplied method signature to the ArgumentProvider and return the resulting
     * string array of parameter types.
     *
     * @param signature user supplied method signature
     * @param includeNanme     whether to include the methods name as a string
     * @return String array containing the parsed parameter type names
     */
    public static String[] getArgumentTypes(String signature, boolean includeName)
    {
        String[] types = null;

        try
        {
            types = argumentProvider.getArgumentTypes(signature, includeName);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return types;
    }

    /**
     * Pass the user supplied method signature to the ArgumentProvider and return the resulting
     * method name parsed from the signature.
     *
     * @param signature user supplied method signature
     * @return the method name that was contained in the signature
     */
    public static String getMethodName(String signature)
    {
        String method = null;

        try
        {
            method = argumentProvider.getMethodName(signature);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return method;
    }

    /**
     * Handle the response object from the MBean server.
     *
     * @param response object returned from the MBean server
     */
    public static void handleResponse(Object response)
    {
        try
        {
            responseHandler.handleResponse(response);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }
    }

    /**
    * Authentication to JMX endpoints is usually handled using a map that contains the authentication
    * parameters. This function is used to prepare such a map by using an explicitly defiend username
    * and password. The default JMX implementation expects the returned Map to contain the key
    * JMXConnector.CREDENTIALS with an associated String array containing the username and the password.
    * However, custom implementations may expect a different format. Therefore, providing the Map
    * through the plugin system allows users to modify the default behavior.
    *
    * @param username the desired username for JMX authentication
    * @param password the desired password for JMX authentication
    * @return environment that should be used during the newClient call
    */
    public static Map<String,Object> getEnv(String username, String password)
    {
        Map<String,Object> map = null;

        try
        {
            map = authenticationProvider.getEnv(username, password);
        }

        catch (PluginException e)
        {
            ExceptionHandler.pluginException(e);
        }

        return map;
    }
}
