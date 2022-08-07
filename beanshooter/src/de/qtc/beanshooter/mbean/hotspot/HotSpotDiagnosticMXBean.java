package de.qtc.beanshooter.mbean.hotspot;

import javax.management.MBeanException;
import javax.management.openmbean.CompositeData;

import de.qtc.beanshooter.mbean.INative;

/**
 * Interface of available HotSpotDiagnosticMXBean operations. Since we only implement a subset of the
 * actually available operations exposed by this MBean, we use a custom interface instead of the original
 * one.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface HotSpotDiagnosticMXBean extends INative
{
    public void dumpHeap(String outputFile, boolean live) throws MBeanException;
    public CompositeData getVMOption(String name) throws MBeanException;
    public void setVMOption(String name, String value) throws MBeanException;
}
