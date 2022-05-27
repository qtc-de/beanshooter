package de.qtc.beanshooter.mbean;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.file.Paths;

import javax.management.ObjectName;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.networking.JarHandler;
import de.qtc.beanshooter.networking.MLetHandler;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.operation.MBeanServerClient;
import de.qtc.beanshooter.utils.Utils;

/**
 * Dispatcher class for generic MBean operations. Contains operations that are supported
 * by each MBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.operation.Dispatcher
{
    protected final IMBean bean;

    /**
     * Create a new dispatcher and configure the MBean it operates on.
     *
     * @param bean MBean to operate on
     */
    public Dispatcher(IMBean bean)
    {
        this.bean = bean;
    }

    /**
     * Print detailed information about the MBean.
     */
    public void info()
    {
        String jarFile = bean.getJarName();

        Logger.printlnYellow(bean.getName());
        Logger.increaseIndent();

        Logger.printlnMixedBlueYellow("Object Name:", "\t", bean.getObjectName().toString());
        Logger.printlnMixedBlueYellow("Class Name:", "\t", bean.getMBeanClass());

        if( jarFile != null )
            Logger.printlnMixedBlueYellow("Jar File:", "\t", "available (" + jarFile + ")");
        else
            Logger.printlnMixedBlueRed("Jar File:", "\t", "not available");

        Logger.decreaseIndent();
    }

    /**
     * Determine whether the configured MBean is registered on the server.
     *
     * @return true if MBean is registered, false otherwise
     */
    public boolean isDeployed()
    {
        ObjectName mBeanObjectName = bean.getObjectName();

        MBeanServerClient mBeanServerClient = getMBeanServerClient();
        return mBeanServerClient.isRegistered(mBeanObjectName);
    }

    /**
     * Check whether the configured MBean is registered on the MBeanServer and print
     * an according status message.
     */
    public void status()
    {
        if( isDeployed() )
        {
            String className = bean.getMBeanClass();
            ObjectName mBeanObjectName = bean.getObjectName();

            Logger.printlnMixedGreen("MBean Status:", "deployed");
            Logger.increaseIndent();

            Logger.printlnMixedBlue("Class Name:", className);
            Logger.printlnMixedBlue("Object Name:", mBeanObjectName.toString());

            Logger.decreaseIndent();

        }

        else
        {
            Logger.printlnMixedRed("MBean Status:", "not deployed");
        }
    }

    /**
     * Deploy the configured MBean on the remote MBeanServer. If the MBean contains a JarName
     * that is not null, remote deployment may be used.
     */
    public void deploy()
    {
        Logger.printlnBlue("Starting MBean deployment.");
        Logger.lineBreak();
        Logger.increaseIndent();

        String mBeanClassName = bean.getMBeanClass();
        ObjectName mBeanObjectName = bean.getObjectName();

        MBeanServerClient mBeanServerClient = getMBeanServerClient();
        mBeanServerClient.deployMBean(mBeanClassName, mBeanObjectName, bean.getJarName());

        Logger.decreaseIndent();
    }

    /**
     * Remove the configured MBean from the remote MBeanServer.
     */
    public void undeploy()
    {
        ObjectName mBeanObjectName = bean.getObjectName();

        MBeanServerClient mBeanServerClient = getMBeanServerClient();
        mBeanServerClient.unregisterMBean(mBeanObjectName);
    }

    /**
     * This function allows exporting the bean and/or a corresponding MLet HTML file to the file system.
     * This is useful in cases where you cannot use beanshooter as a stager, e.g. when loading an MBean via
     * SMB.
     */
    public void export()
    {
        String current = null;
        JarHandler jarHandler = null;
        MLetHandler mletHandler = null;

        String exportDir = BeanshooterOption.EXPORT_DIR.getValue(".");
        String jarFileName = Paths.get(exportDir, BeanshooterOption.EXPORT_JAR.getValue(bean.getJarName())).toString();
        String mLetFileName =  Paths.get(exportDir, BeanshooterOption.EXPORT_MLET.getValue("index.html")).toString();
        String jarName = (new File(jarFileName)).getName();

        try
        {
            if (BeanshooterOption.EXPORT_JAR.notNull() || BeanshooterOption.EXPORT_MLET.isNull())
            {
                jarHandler = new JarHandler(bean.getJarName(), null);

                current = jarFileName;
                jarHandler.export(jarFileName);
            }

            if (BeanshooterOption.EXPORT_MLET.notNull() || BeanshooterOption.EXPORT_JAR.isNull())
            {
                URL url = Utils.parseUrl(ArgumentHandler.require(BeanshooterOption.EXPORT_URL));
                mletHandler = new MLetHandler(url, bean.getMBeanClass(), jarName, bean.getObjectName().toString(), null);

                current = mLetFileName;
                mletHandler.export(mLetFileName);
            }
        }

        catch( IOException e )
        {
            ExceptionHandler.handleFileWrite(e, current, true);
        }
    }

}
