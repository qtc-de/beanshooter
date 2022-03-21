package de.qtc.beanshooter.plugin.providers;

import de.qtc.beanshooter.cli.Operation;
import de.qtc.beanshooter.plugin.IPayloadProvider;
import de.qtc.beanshooter.utils.YsoIntegration;

/**
 * beanshooters default implementation for a payload provider is the YsoSerialProvider,
 * that generates ysoserial gadgets from the specified command line parameters.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class YsoSerialProvider implements IPayloadProvider
{
     /**
     * Generate a ysoserial gadget from the specified command line parameters. This provider
     * is independent of the action specified on the command line.
     */
    public Object getPayloadObject(Operation action, String name, String args)
    {
        return YsoIntegration.getPayloadObject(name, args);
    }
}
