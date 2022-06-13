package de.qtc.beanshooter.mbean.hotspot;

import java.util.List;

import javax.management.MBeanException;
import com.sun.management.VMOption;

import de.qtc.beanshooter.mbean.INative;

/**
 * Interface of available MLet operations. Since we only implement a subset of the
 * actually available operations exposed by this MBean, we use a custom interface
 * instead of the original one.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public interface HotSpotDiagnosticMXBean extends INative
{
    public void dumpHeap(String outputFile, boolean live) throws MBeanException;
    public List<VMOption> getDiagnosticOptions() throws MBeanException;
    public VMOption getVMOption(String name) throws MBeanException;
    public void setVMOption(String name, String value) throws MBeanException;
}
