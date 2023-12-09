package eu.tneitzel.beanshooter.mbean.tomcat;

import javax.management.MBeanException;

import eu.tneitzel.beanshooter.mbean.INative;

/**
 * General user operations on Apache tomcat are exposed through the MemoryUserDatabaseMBean.
 * This interface contains some of the exposed methods. They are currently not implemented,
 * but may be used in future.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface MemoryUserDatabaseMBean extends INative
{
    public String createGroup(String groupname, String description) throws MBeanException;
    public String createRole(String rolename, String description) throws MBeanException;
    public String createUser(String username, String password, String fullName) throws MBeanException;
    public String findGroup(String groupname) throws MBeanException;
    public String findRole(String rolename) throws MBeanException;
    public String findUser(String username) throws MBeanException;
    public void removeGroup(String groupname) throws MBeanException;
    public void removeRole(String rolename) throws MBeanException;
    public void removeUser(String username) throws MBeanException;
    public void save() throws MBeanException;
}
