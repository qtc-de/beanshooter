package de.qtc.beanshooter.mbean.mlet;

import java.io.IOException;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.util.Set;

import javax.management.MBeanException;
import javax.management.ObjectName;
import javax.management.ReflectionException;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.DynamicMBean;
import de.qtc.beanshooter.mbean.IMBean;
import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.mbean.MBeanInvocationHandler;
import de.qtc.beanshooter.networking.StagerServer;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.utils.Utils;

/**
 * Dispatcher class for MLet MBean operations. Implements operations that are supported
 * by the MLet MBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private final MLetMBean mlet;

    /**
     * Creates the dispatcher that operates on the MLet MBean.
     */
    public Dispatcher()
    {
        super(MBean.MLET);

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        mlet = (MLetMBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                  new Class<?>[] { MLetMBean.class },
                                                  invo);
    }

    /**
     * Helper function that obtains an instance of IMBean used for MLet deployments. The function
     * first checks whether the user specified bean name matches one of the MBeans defined in
     * the MBean enum. In this case, the corresponding member is returned.
     *
     * If the user specified the keyword "custom", the function expects the --object-name, the
     * --class-name and the --jar-file options to be specified on the command line. The function
     * creates an instance of DynamicMBean with this information and returns it.
     *
     * @return instance of IMBean that contains the required information for an deployment.
     */
    private IMBean getMbean()
    {
        String beanName = ArgumentHandler.require( MLetOption.LOAD_BEAN );

        if( !beanName.equals("custom") )
            return MBean.valueOf( beanName.toUpperCase() );

        ArgumentHandler.requireAllOf(MLetOption.LOAD_CLASS_NAME, MLetOption.LOAD_OBJECT_NAME, MLetOption.LOAD_JAR_FILE);

        String jarFilePath = MLetOption.LOAD_JAR_FILE.getValue();
        String objectName = MLetOption.LOAD_OBJECT_NAME.getValue();
        String mBeanClassName = MLetOption.LOAD_CLASS_NAME.getValue();

        return new DynamicMBean(objectName, mBeanClassName, jarFilePath);
    }

    /**
     * Checks whether the target MBean is alreday deployed on the server.
     *
     * @param mbean MBean to check for
     * @return true if already deployed, false otherwise
     */
    private boolean targetDeployed(IMBean mbean)
    {
        de.qtc.beanshooter.mbean.Dispatcher dispatcher = new de.qtc.beanshooter.mbean.Dispatcher(mbean);
        return dispatcher.isDeployed();
    }

    /**
     * Load the specified MBean from the specified URL. The URL can be of any protocol e.g. http, https, file...
     * When using the http protocol and an locally available address, the function attempts to open a listener
     * for the specified URL.
     *
     * The specified MBean is only loaded, not deployed.
     *
     * @param mbean MBean to load from the specified URL
     * @param urlString URL to load the MBean from
     */
    public void loadMBeanFromURL(IMBean mbean, String urlString)
    {
        if( targetDeployed(mbean) )
        {
            Logger.printlnMixedYellow("Requested MBean", mbean.getObjectName().toString(), "is already deployed.");
            return;
        }

        if( !isDeployed() )
        {
            deploy();
            Logger.lineBreak();
        }

        URL url = Utils.parseUrl(urlString);

        String mBeanClassName = mbean.getMBeanClass();
        ObjectName mBeanObjectName = mbean.getObjectName();
        String jarFile = mbean.getJarName();

        int port = url.getPort();
        String host = url.getHost();
        String protocol = url.getProtocol();

        Logger.printlnMixedBlue("Loading MBean from", urlString);
        Logger.lineBreak();
        Logger.increaseIndent();

        if( !BeanshooterOption.DEPLOY_NO_STAGER.getBool() && protocol.equals("http") && Utils.isLocal(host) )
        {
            StagerServer server = new StagerServer(host, port, false);
            server.start(urlString, jarFile ,mBeanClassName, mBeanObjectName.toString());
        }

        try
        {
            Set<Object> result = mlet.getMBeansFromURL(url);

            for(Object o : result)
            {
                if( o instanceof Exception)
                    throw (Exception)o;
            }
        }

        catch(MBeanException e)
        {
            Throwable t = ExceptionHandler.getCause(e);

            Logger.resetIndent();
            Logger.eprintMixedYellow("Caught", t.getClass().getName(), "while invoking ");
            Logger.printlnPlainBlue("getMBeansFromURL");

            if( t instanceof java.net.NoRouteToHostException )
            {
                Logger.eprintlnMixedBlue("MBeanServer is unable to connect to", urlString + ".");
            }

            else if( t instanceof java.net.ConnectException )
            {
                if( t.getMessage().contains("Connection refused") )
                    Logger.eprintlnMixedBlue("Target", urlString, "refused the connection.");

                else
                    ExceptionHandler.unknownReason(e);
            }

            else if( t instanceof javax.management.ServiceNotFoundException )
            {
                if( t.getMessage().contains("MLET tag not defined in file") )
                {
                    if( url.getProtocol().equals("file") )
                        Logger.eprintlnMixedBlue("The specified resource", urlString, "was found, but is not a valid MLET resource.");

                    else
                        Logger.eprintlnMixedYellow("The specified resource", urlString, "was either not found or is not a valid MLET resource.");
                }

                else
                {
                    ExceptionHandler.unknownReason(e);
                }
            }

            else if( t instanceof java.io.FileNotFoundException )
            {
                Logger.printlnMixedBlue("MBeanServer is unable to find resource", urlString);
            }

            else if( t instanceof IOException )
            {
                if( t.getMessage().contains("Invalid Http response") )
                    Logger.eprintlnMixedBlue("The specified endpoint", urlString, "returned an invalid HTTP response.");

                else
                    ExceptionHandler.unknownReason(e);
            }

            else
            {
                ExceptionHandler.unknownReason(e);
            }

            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }

        catch(ReflectionException e)
        {
            Logger.lineBreak();
            Logger.resetIndent();

            Logger.eprintlnMixedYellow("Caught", "ReflectionException", "while loading MBean.");
            Logger.eprintlnMixedBlue("This usually means that the supplied MBean class", "was not", "valid.");
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }

        catch(Exception e)
        {
            ExceptionHandler.unexpectedException(e, "loading", "MBean", true);
        }

        finally
        {
            Logger.decreaseIndent();
        }
    }

    /**
     * Wrapper around the loadMBeanFromURL function that requires arguments. Uses the command line specified
     * URL and the command line specified MBean to load.
     */
    public void loadMBeanFromURL()
    {
        String url = ArgumentHandler.require(MLetOption.LOAD_URL);
        IMBean bean = getMbean();

        loadMBeanFromURL(bean, url);
    }
}
