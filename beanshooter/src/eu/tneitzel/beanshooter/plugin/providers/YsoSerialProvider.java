package eu.tneitzel.beanshooter.plugin.providers;

import eu.tneitzel.beanshooter.cli.Operation;
import eu.tneitzel.beanshooter.plugin.IPayloadProvider;
import eu.tneitzel.beanshooter.utils.YsoIntegration;

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
