package de.qtc.beanshooter.utils;

/**
 * The Constant enum stores some constant values that are used by beanshooter.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public enum Constant {

    JMX_MLET_CLASS("javax.management.loading.MLet"),
    JMX_MLET_NAME("DefaultDomain:type=MLet");

    public String value;

    /**
     * Constant values contain a string that represents the constant.
     *
     * @param value constant value represented by the Constant
     */
    Constant(String value)
    {
        this.value = value;
    }
}