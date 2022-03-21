package de.qtc.beanshooter.cli;

/**
 * beanshooter was designed with extensibility in mind. The argument layout is centered
 * around operations that can be invoked on MBeans available within the MBean server. For
 * each MBean, beanshooter may defines an enum that implements the Operation interface.
 * This enum contains the operations that are supported by the corresponding MBean and needs
 * to make the interface functions available. beanshooter can then integrate them into the
 * argument layout automatically.
 *
 * Apart from adding the enum implementing Operation, the MBean must also be registered within
 * the de.qtc.beanshooter.mbean.MBean class. It is recommended to look at the already existing
 * MBean implementations in the de.qtc.beanshooter.mbean package.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface Operation
{
    public String getName();
    public String getDescription();
    public boolean containsOption(Option option);
    public void invoke();
}