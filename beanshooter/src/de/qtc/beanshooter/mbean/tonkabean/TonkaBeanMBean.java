package de.qtc.beanshooter.mbean.tonkabean;

import java.util.Map;

import javax.management.MBeanException;
import javax.management.RuntimeMBeanException;

/**
 * Interface of supported TonkaBean operations. We could also import it from the TonkaBean package, but defining
 * it here demonstrates better which components are required for registering a new MBean with beanshooter. This
 * could probably be helpful for new developers in future.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface TonkaBeanMBean
{
    public String ping() throws MBeanException;
    public String[] shellInit() throws MBeanException;
    public String toServerDir(String cwd, String change) throws MBeanException, RuntimeMBeanException;

    public byte[] executeCommand(String[] cmd, String cwd, Map<String,String> env) throws MBeanException;
    public void executeCommandBackground(String[] cmd, String cwd, Map<String,String> env) throws MBeanException ;

    public byte[] downloadFile(String filename) throws MBeanException;
    public String uploadFile(String destination, byte[] content) throws MBeanException;
}