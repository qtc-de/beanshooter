package de.qtc.beanshooter.mbean.tonkabean;

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
    public String version() throws MBeanException;
    public String[] shellInit() throws MBeanException;
    public String toServerDir(String cwd, String change) throws MBeanException, RuntimeMBeanException;

    public byte[] executeCommand(String[] cmd, String cwd, String[] env, boolean background) throws MBeanException;

    public byte[] downloadFile(String filename) throws MBeanException;
    public String uploadFile(String destination, String filename, byte[] content) throws MBeanException;
}
