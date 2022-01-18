package de.qtc.beanshooter.mbean.tonkabean;

import java.rmi.UnmarshalException;

import javax.management.MBeanException;
import javax.management.ObjectName;
import javax.management.ReflectionException;

import de.qtc.beanshooter.mbean.MBean;
import de.qtc.beanshooter.operation.MBeanServerClient;

/**
 * Dispatcher class for Tonka MBean operations. Implements operations that are supported
 * by the Tonka MBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Dispatcher extends de.qtc.beanshooter.mbean.Dispatcher
{
    /**
     * Creates the dispatcher that operates on the Tonka MBean.
     */
    public Dispatcher()
    {
        super(MBean.TONKA);
    }

    public void execute()
    {
        ObjectName objectName = bean.getObjectName();

        MBeanServerClient mBeanServerClient = getMBeanServerClient();
        try {
            String result = (String)mBeanServerClient.invoke(objectName, "executeCommand", "id");
            System.out.println(result);
        } catch (MBeanException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ReflectionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (UnmarshalException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }


    public void executeBackground() {}
    public void shell() {}
    public void upload() {}
    public void download() {}
}
