package de.qtc.beanshooter.mbean;

import java.io.IOException;
import java.nio.file.Paths;

import javax.management.ObjectName;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.networking.JarHandler;
import de.qtc.beanshooter.networking.MLetHandler;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.operation.MBeanServerClient;

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
        boolean exported = false;
        String filename = bean.getJarName();

        try
        {
            JarHandler jarHandler = new JarHandler(bean.getJarName(), false, null);

            if( BeanshooterOption.EXPORT_JAR.notNull() )
            {
                filename = BeanshooterOption.EXPORT_JAR.getValue();
                jarHandler.export(filename);
                exported = true;
            }

            String url = BeanshooterOption.EXPORT_URL.getValue("");
            MLetHandler mletHandler = new MLetHandler(url, bean.getMBeanClass(), filename, bean.getObjectName().toString(), false);

            if( BeanshooterOption.EXPORT_MLET.notNull() )
            {
                ArgumentHandler.require(BeanshooterOption.EXPORT_URL);
                mletHandler.export(BeanshooterOption.EXPORT_MLET.getValue());
                exported = true;
            }

            if(exported)
                return;

            ArgumentHandler.require(BeanshooterOption.EXPORT_URL);
            String exportDir = BeanshooterOption.EXPORT_DIR.getValue(".");

            filename = Paths.get(exportDir, filename).toString();
            jarHandler.export(filename);

            filename = Paths.get(exportDir, "index.html").toString();
            mletHandler.export(filename);
        }

        catch( IOException e )
        {
            ExceptionHandler.handleFileWrite(e, filename, true);
        }
    }

}
