package eu.tneitzel.beanshooter.mbean.diagnostic;

import javax.management.MBeanException;

import eu.tneitzel.beanshooter.mbean.INative;

/**
 * The DiagnosticCOmmandMBean interface implements some methods that are usually exposed under the
 * DiagnosticCommand object name. Usually, the amount of exposed methods is quite larger that the
 * methods implemented in this interface and a full list of methods can be obtained by using
 * beanshooters info action together with the diagnostic MBean.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface DiagnosticCommandMBean extends INative
{
    public String compilerDirectivesAdd(String[] directives) throws MBeanException;
    public String jvmtiAgentLoad(String[] paths) throws MBeanException;
    public String vmLog(String[] arguments) throws MBeanException;
    public String vmSystemProperties() throws MBeanException;
    public String vmCommandLine() throws MBeanException;
}
