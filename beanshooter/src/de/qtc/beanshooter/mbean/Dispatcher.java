package de.qtc.beanshooter.mbean;

import javax.management.ObjectName;

import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.MBeanServerClient;

/**
 * Dispatcher class for generic MBean operations. Contains operations that are supported
 * by each MBean.
 * 
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.operation.Dispatcher
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
}
