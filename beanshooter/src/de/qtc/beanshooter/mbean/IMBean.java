package de.qtc.beanshooter.mbean;

import javax.management.ObjectName;

/**
 * To perform operations on an MBean, the corresponding bean needs to be wrapped inside
 * a class that implements the IMBean interface. This can either be a member of the MBean
 * enum (default MBean classes) or an instance of the DynamicMBean class (command line
 * specified MBean).
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IMBean
{
    public ObjectName getObjectName();
    public String getMBeanClass();
    public String getJarName();
    public String getName();
}
