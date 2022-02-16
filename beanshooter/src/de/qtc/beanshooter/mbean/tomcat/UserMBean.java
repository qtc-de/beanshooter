package de.qtc.beanshooter.mbean.tomcat;

import javax.management.MBeanException;

import de.qtc.beanshooter.mbean.INative;

/**
 * Tomcat creates a separate UserMBean for each registered user. This interface
 * contains the methods that are available on the corresponding MBean. They are
 * currently not implemented, but we may use them in future.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface UserMBean extends INative
{
    public void addGroup(String groupname) throws MBeanException;
    public void removeGroup(String groupname) throws MBeanException;
    public void removeRole(String rolename) throws MBeanException;
}