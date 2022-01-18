package de.qtc.beanshooter.mbean;

import java.util.ArrayList;
import java.util.List;

import javax.management.ObjectName;

import de.qtc.beanshooter.cli.Operation;
import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.mbean.mlet.MLetOperation;
import de.qtc.beanshooter.mbean.mlet.MLetOption;
import de.qtc.beanshooter.mbean.tonkabean.TonkaBeanOperation;
import de.qtc.beanshooter.mbean.tonkabean.TonkaBeanOption;
import de.qtc.beanshooter.utils.Utils;

/**
 * Members of the MBean enum represent available MBeans on a remote MBeanServer that beanshooter
 * can operate on. They contain the required information like the ObjectName, the ClassName and
 * the available operations and options.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum MBean implements IMBean
{
    TONKA("tonka",
          "general purpose bean for executing commands and uploading or download files",
          Utils.getObjectName("MLetTonkaBean:name=TonkaBean,id=1"),
          "de.qtc.beanshooter.tonkabean.TonkaBean",
          "tonka-bean-3.0.0-jar-with-dependencies.jar",
          TonkaBeanOperation.values(),
          TonkaBeanOption.values()
         ),

    MLET("mlet",
         "default JMX bean that can be used to load additional beans dynamically",
         Utils.getObjectName("DefaultDomain:type=MLet"),
         "javax.management.loading.MLet",
         null,
         MLetOperation.values(),
         MLetOption.values()
        );

    private String name;
    private String description;
    private ObjectName objectName;
    private String mBeanClass;
    private String jarFileName;
    private Operation[] operations;
    private Option[] options;

    /**
     * Create a new MBean object.
     *
     * @param name display name of the corresponding MBean
     * @param description short description for the help menu
     * @param objName ObjectName used by the MBean
     * @param mBeanClass Class name implemented by the MBean
     * @param jarName optional jar name that implements the MBean
     * @param operations available operations on this MBean
     * @param options available options on this MBean
     */
    MBean(String name, String description, ObjectName objName, String mBeanClass, String jarName, Operation[] operations, Option[] options)
    {
        this.name = name;
        this.description = description;
        this.operations = operations;
        this.objectName = objName;
        this.mBeanClass = mBeanClass;
        this.jarFileName = jarName;
        this.options = options;
    }

    /**
     * Return the display name of the MBean.
     *
     * @return display name of the MBean
     */
    public String getName()
    {
        return name;
    }

    /**
     * Return the description name of the MBean.
     *
     * @return description of the MBean
     */
    public String getDescription()
    {
        return description;
    }

    /**
     * Return the ObjectName of the MBean.
     *
     * @return ObjectName of the MBean
     */
    public ObjectName getObjectName()
    {
        return this.objectName;
    }

    /**
     * Return the Class name of the MBean.
     *
     * @return Class name of the MBean
     */
    public String getMBeanClass()
    {
        return this.mBeanClass;
    }

    /**
     * Return the jar name of the MBean.
     *
     * @return jar name of the MBean
     */
    public String getJarName()
    {
        return this.jarFileName;
    }

    /**
     * Return the available options on the MBean.
     *
     * @return available options
     */
    public Option[] getOptions()
    {
        return this.options;
    }

    /**
     * Return the available operations on the MBean.
     *
     * @return available operations
     */
    public Operation[] getOperations()
    {
        return operations;
    }

    /**
     * Find a member of the MBean enum by name.
     *
     * @param beanName name of the MBean to look for
     * @return MBean member that matches the specified name
     */
    public static MBean getMBean(String beanName)
    {
        MBean returnValue = null;

        for(MBean bean : MBean.values())
        {
            if( bean.name.equals(beanName) )
                returnValue = bean;
        }

        return returnValue;
    }

    /**
     * Return a list of available MBean members.
     *
     * @return List of avaulable MBean members
     */
    public static List<String> getBeanNames()
    {
        List<String> mBeanNames = new ArrayList<String>();

        for( MBean bean : MBean.values())
            mBeanNames.add(bean.getName());

        return mBeanNames;
    }
}
