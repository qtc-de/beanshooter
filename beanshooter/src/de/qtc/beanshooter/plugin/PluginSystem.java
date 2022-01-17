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

import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.MalformedPluginException;
import de.qtc.beanshooter.io.Logger;
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
        socketFactoryProvider = new DefaultSocketFactoryProvider();

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
        }

        if(!inUse) {
            Logger.eprintMixedBlue("Plugin", pluginPath, "was successfully loaded, but is ");
            Logger.eprintlnPlainYellow("not in use.");
            Logger.eprintlnMixedYellow("Plugins should implement at least one of the", "IMBeanServerProvider or ISocketFactoryProvider", "interfaces.");
        }
    }

    /**
     * Returns the IMBeanServerProvider according to the specified command line arguments.
     *
     * @return IMBeanServerProvider according to the specified command lien arguments.
     */
    private static IMBeanServerProvider selectProvider()
    {
        if( Option.CONN_JMXMP.getBool() )
            return new JMXMPProvider();

        return new RMIProvider();
    }

    /**
     * Returns the RMIClientSocketFactory that is used for RMI connections. The factory returned by this function
     * is used for all direct RMI calls. So e.g. if you call the registry or another RMI endpoint directly. If you
     * first lookup a bound name and use the obtained reference to make calls on the object, another factory is used
     * (check the getDefaultClientSocketFactory function for more details).
     *
     * @return RMIClientSocketFactory that is used for direct RMI calls
     */
    public static MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env)
    {
        return mBeanServerProvider.getMBeanServerConnection(host, port, env);
    }

    /**
     * Returns the RMIClientSocketFactory that is used for RMI connections. The factory returned by this function
     * is used for all direct RMI calls. So e.g. if you call the registry or another RMI endpoint directly. If you
     * first lookup a bound name and use the obtained reference to make calls on the object, another factory is used
     * (check the getDefaultClientSocketFactory function for more details).
     *
     * @return RMIClientSocketFactory that is used for direct RMI calls
     */
    public static RMIClientSocketFactory getClientSocketFactory()
    {
        return socketFactoryProvider.getClientSocketFactory();
    }

    /**
     * Returns the RMISocketFactory that is used for all RMI connections that use the default RMISocketFactory. The
     * factory returned by this function is used when you perform RMI actions on a remote object reference that was
     * obtained from the RMI registry and the RMI server did not assign a custom socket factory to the object.
     *
     * @return RMISocketFactory that is used for "after lookup" RMI calls
     */
    public static RMISocketFactory getDefaultSocketFactory(String host, int port)
    {
        return socketFactoryProvider.getDefaultSocketFactory(host, port);
    }

    /**
     * Java RMI also contains a default implementation for SSL protected RMI communication. If the server uses the
     * corresponding SocketFactory on the server side, the RMI client does too and the only way to overwrite the default
     * SSLSocketFactory is by setting a Java property. Therefore, this function should return the name of a class that
     * you want to use as your default SSLSocketFactory. Notice that the factory needs to be available on the class path
     * and it is not sufficient to define it within the plugin.
     *
     * @return String that indicates the desired SSLSocketFactories class name
     */
    public static String getDefaultSSLSocketFactory(String host, int port)
    {
        return socketFactoryProvider.getDefaultSSLSocketFactory(host, port);
    }
}