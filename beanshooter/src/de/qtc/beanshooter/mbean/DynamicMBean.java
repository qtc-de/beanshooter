package de.qtc.beanshooter.mbean;

import javax.management.ObjectName;

import de.qtc.beanshooter.utils.Utils;

/**
 * MBean operations usually require an MBean from the MBean enum defined in this package. The beans
 * in this enum contain all the required information to perform operations on them. However, users can
 * also specify the required information (ObjectName, ClassName) to perform operations on a MBean on the
 * command line.
 * 
 * In these cases, beanshooter creates a DynamicMBean object. DynamicMBean implements the IMBean interface
 * that is also implemented by the MBean enum. This allows to use instances of both classes within of MBean
 * operations.
 * 
 * @author Tobias Neitzel (@qtc_de)
 */
public class DynamicMBean implements IMBean 
{
	private final ObjectName objectName;
	private final String mBeanClassName;
	private final String jarFile;
	
	/**
	 * A DynamicMBean requires an ObjectName, a MBean class name and optionally the path to a jar file
	 * that implements the MBean.
	 * 
	 * @param objectName ObjectName of the corresponding MBean (as String)
	 * @param mBeanClassName Class name of the corresponding MBean
	 * @param jarFile path to a jar file that implements the MBean (may be null)
	 */
	public DynamicMBean(String objectName, String mBeanClassName, String jarFile)
	{
		this(Utils.getObjectName(objectName), mBeanClassName, jarFile);
	}
	
	/**
	 * A DynamicMBean requires an ObjectName, a MBean class name and optionally the path to a jar file
	 * that implements the MBean.
	 * 
	 * @param objectName ObjectName of the corresponding MBean
	 * @param mBeanClassName Class name of the corresponding MBean
	 * @param jarFile path to a jar file that implements the MBean (may be null)
	 */
	public DynamicMBean(ObjectName objectName, String mBeanClassName, String jarFile)
	{
		this.objectName = objectName;
		this.mBeanClassName = mBeanClassName;
		this.jarFile = jarFile;
	}

	/**
	 * Return the configured ObjectName.
	 */
	@Override
	public ObjectName getObjectName()
	{
		return objectName;
	}

	/**
	 * Return the configured ClassName.
	 */
	@Override
	public String getMBeanClass()
	{
		return mBeanClassName;
	}

	/**
	 * Return the configured JarName.
	 */
	@Override
	public String getJarName()
	{
		return jarFile;
	}
}
