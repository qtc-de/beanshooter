package de.qtc.beanshooter.mbean;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.management.MBeanAttributeInfo;
import javax.management.MBeanInfo;
import javax.management.MBeanOperationInfo;
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
     * Print detailed and locally known information about the MBean.
     */
    public void stats()
    {
        String jarFile = bean.getJarName();

        Logger.printlnMixedYellow("MBean:", bean.getName());
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
     * The info action obtains an MBeanInfo object from the MBeanServer and outputs information on
     * the available attributes and methods on the corresponding MBean.
     */
    public void info()
    {
        List<String> keywords = Arrays.asList(ArgumentHandler.getInstance().getFromConfig("keywords").split(" "));
        List<String> methodKeywords = Arrays.asList(ArgumentHandler.getInstance().getFromConfig("methodKeywords").split(" "));

        if (BeanshooterOption.ATTR_KEYWORDS.notNull())
            keywords = Arrays.asList(BeanshooterOption.ATTR_KEYWORDS.<String>getValue().split(" "));

        if (BeanshooterOption.ATTR_KEYWORDS.notNull())
            methodKeywords = Arrays.asList(BeanshooterOption.ATTR_METHOD_KEYWORDS.<String>getValue().split(" "));

        MBeanServerClient conn = getMBeanServerClient();
        MBeanInfo info = conn.getMBeanInfo(bean.getObjectName());
        MBeanAttributeInfo[] attrs = info.getAttributes();
        MBeanOperationInfo[] opInfos = info.getOperations();

        if (!BeanshooterOption.ATTR_HARVEST.getBool())
        {
            Logger.lineBreak();
            Logger.printlnMixedYellow("MBean Class:", info.getClassName());
            Logger.printlnMixedYellow("ObjectName:", bean.getObjectName().toString());
            Logger.lineBreak();
            Logger.increaseIndent();

            Logger.printlnYellow("Attributes:");
            Logger.increaseIndent();

            if (attrs.length != 0)
            {
                boolean output = false;

                for (MBeanAttributeInfo attr : attrs)
                {
                    if (BeanshooterOption.ATTR_WRITEABLE.getBool() && !attr.isWritable())
                        continue;

                    if (listContains(keywords, attr.getName()))
                        Logger.printMixedRedFirst(attr.getName(), "(type: ");
                    else
                        Logger.printMixedBlueFirst(attr.getName(), "(type: ");

                    Logger.printPlainMixedYellowFirst(attr.getType(), ", writable: ");

                    if (attr.isWritable())
                        Logger.printPlainGreen("true");
                    else
                        Logger.printPlainRed("false");

                    Logger.printlnPlain(")");
                    output = true;
                }

                if (!output)
                    Logger.printlnBlue("None");
            }

            else
            {
                Logger.printlnBlue("None");
            }

            Logger.decreaseIndent();
            Logger.lineBreak();
            Logger.printlnYellow("Operations:");
            Logger.increaseIndent();

            if (opInfos.length != 0)
            {
                for (MBeanOperationInfo opInfo : opInfos)
                {
                    if (listContains(methodKeywords, opInfo.getName()))
                        Logger.printlnRed(Utils.getMethodString(opInfo));
                    else
                        Logger.printlnBlue(Utils.getMethodString(opInfo));
                }
            }

            else
            {
                Logger.printlnBlue("None");
            }

            Logger.decreaseIndent();
            Logger.decreaseIndent();
        }

        else
        {
            if (attrs.length != 0)
            {
                for (MBeanAttributeInfo attr : attrs)
                {
                    if (BeanshooterOption.ATTR_WRITEABLE.getBool() && !attr.isWritable())
                        continue;

                    if (!listContains(keywords, attr.getName()))
                        continue;

                    Logger.print("Attribute:");
                    Logger.printPlainBlue(bean.getObjectName().toString());
                    Logger.printPlainMixedRed(" ::", attr.getName());
                    Logger.printPlainMixedYellow("(type:", attr.getType());
                    Logger.printPlainMixedYellow(", writable:", String.valueOf(attr.isWritable()));
                    Logger.printlnPlain(")");
                }
            }

            if (opInfos.length != 0)
            {
                for (MBeanOperationInfo opInfo : opInfos)
                {
                    if (!listContains(methodKeywords, opInfo.getName()))
                        continue;

                    Logger.print("Method:");
                    Logger.printPlainBlue(bean.getObjectName().toString());
                    Logger.printlnPlainMixedRed("::", Utils.getMethodString(opInfo));
                }
            }
        }
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
        String jarFileName = Utils.joinIfRelative(exportDir, BeanshooterOption.EXPORT_JAR.getValue(bean.getJarName())).toString();
        String mLetFileName =  Utils.joinIfRelative(exportDir, BeanshooterOption.EXPORT_MLET.getValue("index.html")).toString();
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

    private boolean listContains(List<String> list, String match)
    {
        match = match.toLowerCase();
        list = list.stream().map(String::toLowerCase).collect(Collectors.toList());

        return list.stream().anyMatch(match::contains);
    }
}
