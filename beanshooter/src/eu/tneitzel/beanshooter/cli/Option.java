package eu.tneitzel.beanshooter.cli;

import net.sourceforge.argparse4j.inf.ArgumentAction;
import net.sourceforge.argparse4j.inf.Namespace;

/**
 * beanshooters command line layout contains subparsers for each supported MBean.
 * MBean implementations are responsible for adding their available options within
 * their own package namespace using an enum that implements the Option interface.
 *
 * The enum should contain all available options in the same format as they are
 * stored in the eu.tneitzel.beanshooter.operations.BeanshooterOption enum. beanshooter
 * uses the interface functions to obtain the option values during runtime and to
 * add them to the command line.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface Option
{
    public String name();
    public ArgType getArgType();
    public ArgumentAction argumentAction();
    public boolean getBool();
    public boolean isNull();
    public boolean notNull();
    public OptionGroup optionGroup();
    public String description();
    public String metavar();
    public String getName();
    public <T> T getValue();
    public void setValue(Namespace args, Object def);
    public void setValue(Object value);
    public void setValue(Object value, Object def);
}
