package de.qtc.beanshooter.mbean;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.management.ObjectInstance;
import javax.management.ObjectName;

import de.qtc.beanshooter.cli.Operation;
import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.mbean.diagnostic.DiagnosticCommandOperation;
import de.qtc.beanshooter.mbean.diagnostic.DiagnosticCommandOption;
import de.qtc.beanshooter.mbean.flightrecorder.FlightRecorderOperation;
import de.qtc.beanshooter.mbean.flightrecorder.FlightRecorderOption;
import de.qtc.beanshooter.mbean.hotspot.HotSpotDiagnosticOperation;
import de.qtc.beanshooter.mbean.hotspot.HotSpotDiagnosticOption;
import de.qtc.beanshooter.mbean.mlet.MLetOperation;
import de.qtc.beanshooter.mbean.mlet.MLetOption;
import de.qtc.beanshooter.mbean.tomcat.MemoryUserDatabaseMBeanOperation;
import de.qtc.beanshooter.mbean.tomcat.MemoryUserDatabaseMBeanOption;
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
    DIAGNOSTIC_COMMAND(
            "diagnostic",
            "Diagnostic Command MBean",
             Utils.getObjectName("com.sun.management:type=DiagnosticCommand"),
             new String[]
             {
                     "com.sun.management.internal.DiagnosticCommandImpl",
                     "sun.management.DiagnosticCommandImpl"
             },
             null,
             DiagnosticCommandOperation.values(),
             DiagnosticCommandOption.values()
            ),

    HOTSPOT_DIAGNOSTIC(
            "hotspot",
            "HotSpot Diagnostic MBean",
             Utils.getObjectName("com.sun.management:type=HotSpotDiagnostic"),
             new String[]
             {
                     "com.sun.management.internal.HotSpotDiagnostic",
                     "sun.management.HotSpotDiagnostic"
             },
             null,
             HotSpotDiagnosticOperation.values(),
             HotSpotDiagnosticOption.values()
            ),

    MLET("mlet",
         "default JMX bean that can be used to load additional beans dynamically",
         Utils.getObjectName("DefaultDomain:type=MLet"),
         new String[]
         {
                 "javax.management.loading.MLet",
         },
         null,
         MLetOperation.values(),
         MLetOption.values()
        ),

    FLIGHT_RECORDER(
            "recorder",
            "jfr Flight Recorder MBean",
             Utils.getObjectName("jdk.management.jfr:type=FlightRecorder"),
             new String[]
             {
                     "jdk.management.jfr.FlightRecorderMXBeanImpl",
             },
             null,
             FlightRecorderOperation.values(),
             FlightRecorderOption.values()
            ),

    MEMORY_USER_DATABASE(
           "tomcat",
           "tomcat MemoryUserDatabaseMBean used for user management",
            Utils.getObjectName("Users:type=UserDatabase,database=UserDatabase"),
            new String[]
            {
                    "org.apache.catalina.mbeans.MemoryUserDatabaseMBean",
            },
            null,
            MemoryUserDatabaseMBeanOperation.values(),
            MemoryUserDatabaseMBeanOption.values()
           ),

    TONKA("tonka",
          "general purpose bean for executing commands and uploading or download files",
          Utils.getObjectName("MLetTonkaBean:name=TonkaBean,id=1"),
          new String[]
          {
                  "de.qtc.beanshooter.tonkabean.TonkaBean",
          },
          "tonka-bean-4.0.0-jar-with-dependencies.jar",
          TonkaBeanOperation.values(),
          TonkaBeanOption.values()
         );

    private String name;
    private String description;
    private ObjectName objectName;
    private String[] mBeanClasses;
    private String jarFileName;
    private Operation[] operations;
    private Option[] options;

    /**
     * Create a new MBean object.
     *
     * @param name display name of the corresponding MBean
     * @param description short description for the help menu
     * @param objName ObjectName used by the MBean
     * @param mBeanClasses Class names implemented by the MBean
     * @param jarName optional jar name that implements the MBean
     * @param operations available operations on this MBean
     * @param options available options on this MBean
     */
    MBean(String name, String description, ObjectName objName, String[] mBeanClasses, String jarName, Operation[] operations, Option[] options)
    {
        this.name = name;
        this.description = description;
        this.operations = operations;
        this.objectName = objName;
        this.mBeanClasses = mBeanClasses;
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
        return this.mBeanClasses[0];
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
     * Find a member of the MBean enum by it's ObjectName.
     *
     * @param objectName ObjectName to loom for
     * @return MBean member that matches the specified ObjectName
     */
    public static MBean getMBean(ObjectName objectName)
    {
        MBean returnValue = null;

        for(MBean bean : MBean.values())
        {
            if( bean.objectName.equals(objectName) )
                returnValue = bean;
        }

        return returnValue;
    }

    /**
     * Return a list of available MBean members.
     *
     * @return List of available MBean members
     */
    public static List<String> getBeanNames()
    {
        List<String> mBeanNames = new ArrayList<String>();

        for( MBean bean : MBean.values())
            mBeanNames.add(bean.getName());

        return mBeanNames;
    }

    /**
     * Return a list of available MBean classes.
     *
     * @return List of available MBean classes
     */
    public static List<String> getBeanClasses()
    {
        List<String> mBeanNames = new ArrayList<String>();

        for( MBean bean : MBean.values())
        {
            for (String className : bean.mBeanClasses)
            {
                mBeanNames.add(className);
            }
        }

        return mBeanNames;
    }

    /**
     * Return a list of available MBean members that have a jar file defined.
     *
     * @return List of available MBean members that have a jar file defined
     */
    public static List<String> getLoadableBeanNames()
    {
        List<String> mBeanNames = new ArrayList<String>();

        for( MBean bean : MBean.values())
        {
            if( bean.jarFileName == null )
                continue;

            mBeanNames.add(bean.getName());
        }

        return mBeanNames;
    }

    /**
     * During beanshooters enum operation, beanshooter attempts to list available MBeans on the
     * remote MBeanServer. The result (Set<ObjectInstance>) is passed into this function, which
     * checks whether one of the available MBeans is present within the MBean enum. If this is
     * the case, beanshooter checks for an Operation with the name ENUM within the MBean operations.
     * If such an Operation is found, it is invoked.
     *
     * The idea behind this is to allow triggering additional enum actions for specific MBeans.
     * E.g. enumerating tomcat users on a JMX endpoint only makes sense if the corresponding
     * MBean is present. With the performEnumActions functions, we can just implement an ENUM
     * operation for the MemoryUserDatabaseMBean and it triggers automatically when this bean is
     * present.
     *
     * @param instances enumerated MBean instances available on the remote MBeanServer
     */
    public static void performEnumActions(Set<ObjectInstance> instances)
    {
        for(ObjectInstance instance : instances)
        {
            MBean mbean = MBean.getMBean(instance.getObjectName());

            if(mbean == null)
                continue;

            for(Operation op : mbean.getOperations())
            {
                if(op.getName().equals("ENUM"))
                {
                    Logger.lineBreak();
                    op.invoke();
                }
            }
        }
    }
}
