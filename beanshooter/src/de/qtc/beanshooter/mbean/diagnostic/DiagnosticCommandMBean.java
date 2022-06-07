package de.qtc.beanshooter.mbean.diagnostic;

import javax.management.MBeanException;

import de.qtc.beanshooter.mbean.INative;

/**
 * Interface of available MLet operations. Since we only implement a subset of the
 * actually available operations exposed by this MBean, we use a custom interface
 * instead of the original one.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface DiagnosticCommandMBean extends INative
{
    public String compilerDirectivesAdd(String[] directives) throws MBeanException;
    public String jvmtiAgentLoad(String[] paths) throws MBeanException;
    public String vmLog(String[] arguments) throws MBeanException;
}