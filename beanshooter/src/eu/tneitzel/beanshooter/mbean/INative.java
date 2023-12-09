package eu.tneitzel.beanshooter.mbean;

import javax.management.MBeanException;

/**
 * The INative interface contains methods that are supported by each MBean natively.
 * It is supposed to be extended by MBean-interfaces that contain specific methods
 * for the MBean they are assigned to.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface INative
{
    public Object getAttribute(String name) throws MBeanException;
}
