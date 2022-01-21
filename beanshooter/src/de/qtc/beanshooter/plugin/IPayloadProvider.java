package de.qtc.beanshooter.plugin;

import de.qtc.beanshooter.cli.Operation;

/**
 * The IPayloadProvider interface is used during beanshooter operations that perform deserialization attacks.
 * It is used to obtain the payload object that is send during deserialization attacks.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IPayloadProvider
{
    Object getPayloadObject(Operation action, String name, String args);
}
