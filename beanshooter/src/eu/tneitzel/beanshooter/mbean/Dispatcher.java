package eu.tneitzel.beanshooter.mbean;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import javax.management.Attribute;
import javax.management.MBeanAttributeInfo;
import javax.management.MBeanException;
import javax.management.MBeanInfo;
import javax.management.MBeanOperationInfo;
import javax.management.ObjectName;
import javax.management.ReflectionException;

import eu.tneitzel.beanshooter.cli.ArgumentHandler;
import eu.tneitzel.beanshooter.exceptions.ExceptionHandler;
import eu.tneitzel.beanshooter.io.Logger;
import eu.tneitzel.beanshooter.networking.JarHandler;
import eu.tneitzel.beanshooter.networking.MLetHandler;
import eu.tneitzel.beanshooter.operation.BeanshooterOption;
import eu.tneitzel.beanshooter.operation.MBeanServerClient;
import eu.tneitzel.beanshooter.plugin.PluginSystem;
import eu.tneitzel.beanshooter.utils.Utils;

/**
 * Dispatcher class for generic MBean operations. Contains operations that are supported
 * by each MBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends eu.tneitzel.beanshooter.operation.Dispatcher
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
     * Sets or gets an attribute on the targeted MBean.
     */
    public void attr()
    {
        Attribute attrObj = null;

        String attrName = ArgumentHandler.require(BeanshooterOption.ATTR_ATTRIBUTE);
        String attrValue = BeanshooterOption.ATTR_VALUE.getValue(null);
        String typeName = BeanshooterOption.ATTR_TYPE.getValue("String");

        if (attrValue != null)
        {
            String signature = String.format("void dummy(%s p1)", typeName);
            PluginSystem.getArgumentTypes(signature);
            Object[] argumentArray = PluginSystem.getArgumentArray(new String[] { attrValue });

            attrObj = new Attribute(attrName, argumentArray[0]);
        }

        MBeanServerClient client = getMBeanServerClient();

        try
        {
            if (attrObj != null)
                client.setAttribute(bean.getObjectName(), attrObj);

            else
            {
                Object result = client.getAttribute(bean.getObjectName(), attrName);

                if( result != null )
                    PluginSystem.handleResponse(result);
                else
                    Logger.println("null");
            }
        }

        catch (MBeanException | ReflectionException | IOException e)
        {
            Logger.printlnMixedYellow("Caught", e.getClass().getName(), String.format("while obtaining attribute %s from %s", attrName, bean.getObjectName()));
            Logger.println("beanshooter does not handle exceptions for custom method invocations.");
            ExceptionHandler.stackTrace(e);
        }
    }

    /**
     * Invoke a method on the MBean. This allows the user to manually specify a method signature
     * and the desired arguments and invokes the corresponding call on the MBeanServer.
     */
    public void invoke()
    {
        String signature = ArgumentHandler.require(BeanshooterOption.INVOKE_METHOD);
        List<String> argumentStringArray = BeanshooterOption.INVOKE_METHOD_ARGS.getValue();

        String[] argumentTypes = PluginSystem.getArgumentTypes(signature);
        Object[] argumentArray = PluginSystem.getArgumentArray(argumentStringArray.toArray(new String[0]));
        String methodName = PluginSystem.getMethodName(signature);

        MBeanServerClient client = getMBeanServerClient();

        try
        {
            Object result = client.invoke(bean.getObjectName(), methodName, argumentTypes, argumentArray);

            if( result != null )
                PluginSystem.handleResponse(result);
            else
                Logger.printlnBlue("Call was successful.");
        }

        catch (MBeanException | ReflectionException | IOException e)
        {
            Logger.printlnMixedYellow("Caught", e.getClass().getName(), String.format("while invoking %s on %s.", methodName, bean.getObjectName().toString()));
            Logger.println("beanshooter does not handle exceptions for custom method invocations.");
            ExceptionHandler.stackTrace(e);
        }
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
