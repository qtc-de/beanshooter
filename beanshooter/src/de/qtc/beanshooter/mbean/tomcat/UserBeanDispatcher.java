package de.qtc.beanshooter.mbean.tomcat;

import java.lang.reflect.Proxy;

import javax.management.MBeanException;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.mbean.DynamicMBean;
import de.qtc.beanshooter.mbean.IMBean;
import de.qtc.beanshooter.mbean.MBeanInvocationHandler;

/**
 * Dispatch operations on the UserMBean. This dispatcher is a little bit different from the
 * other defined dispatchers in this project, since it is not intended to be launched from
 * the command line. The problem here is, that the ObjectName of the associated MBean contains
 * the username of the targeted user. Therefore, it is dynamic and does not align with the
 * MBean layout used by beanshooter.
 *
 * This dispatcher is intended to be accessed by other dispatchers (that are invokable from the
 * command line) by using the getDispatcher method.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class UserBeanDispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    private final UserMBean userBean;

     /**
     * Creates the dispatcher that operates on the UserMBean.
     */
    public UserBeanDispatcher(IMBean bean)
    {
        super(bean);

        MBeanInvocationHandler invo = new MBeanInvocationHandler(bean.getObjectName(), getMBeanServerConnection());
        userBean = (UserMBean) Proxy.newProxyInstance(Dispatcher.class.getClassLoader(),
                                                            new Class<?>[] { UserMBean.class },
                                                            invo);
    }

    /**
     * Get the username attribute of the associated MBean.
     *
     * @return username
     */
    public String getName()
    {
        try
        {
            return (String) userBean.getAttribute("username");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "obtaining", "tomcat username", false);
        }

        return "unknown error";
    }

    /**
     * Get the assigned roles of the associated MBean.
     *
     * @return the users roles as an array of String
     */
    public String[] getRoles()
    {
        try
        {
            return (String[]) userBean.getAttribute("roles");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "obtaining", "tomcat user roles", false);
        }

        return new String[] {};
    }

    /**
     * Get the assigned groups of the associated MBean.
     *
     * @return the users groups as an array of String
     */
    public String[] getGroups()
    {
        try
        {
            return (String[]) userBean.getAttribute("groups");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "obtaining", "tomcat user roles", false);
        }

        return new String[] {};
    }

    /**
     * Obtain the password from the associated MBean.
     *
     * @return the users password
     */
    public String getPassword()
    {
        try
        {
            return (String) userBean.getAttribute("password");
        }

        catch (MBeanException e)
        {
            ExceptionHandler.unexpectedException(e, "obtaining", "tomcat user roles", false);
        }

        return null;
    }

    /**
     * Tomcat creates one UserMBean for each user. The MBean contains the username within it's
     * object name. This makes it impossible to define the bean within the MBean enum, as we do
     * it for other MBeans. Instead we use this helper function to generate a DynamicMBean that
     * uses the specified ObjectName.
     *
     * @param userObjectName object name of the UserMBean
     * @return dispatcher instance
     */
    public static UserBeanDispatcher getDispatcher(String userObjectName)
    {
        DynamicMBean dynBean = new DynamicMBean(userObjectName, "org.apache.catalina.mbeans", null);

        return new UserBeanDispatcher(dynBean);
    }
}
