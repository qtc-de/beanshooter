package de.qtc.beanshooter.mbean.mlet;

import java.net.URL;
import java.util.Set;

import javax.management.MBeanException;

/**
 * Interface of available MLet operations. Since we only implement a subset of the
 * actually available operations exposed by this MBean, we use a custom interface
 * instead of the original one.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface MLetMBean
{
    public Set<Object> getMBeansFromURL(URL url) throws MBeanException;
}
