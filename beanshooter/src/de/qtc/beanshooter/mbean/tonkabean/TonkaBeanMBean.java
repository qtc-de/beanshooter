package de.qtc.beanshooter.mbean.tonkabean;

import java.io.File;
import java.util.Map;

import javax.management.MBeanException;

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
    public String username() throws MBeanException;
    public File toServerDir(File cwd) throws MBeanException;

    public byte[] executeCommand(String[] cmd, File cwd, Map<String,String> env) throws MBeanException;
    public void executeCommandBackground(String[] cmd, File cwd, Map<String,String> env) throws MBeanException ;

    public byte[] downloadFile(String filename) throws MBeanException;
    public String uploadFile(String destination, byte[] content) throws MBeanException;
}
