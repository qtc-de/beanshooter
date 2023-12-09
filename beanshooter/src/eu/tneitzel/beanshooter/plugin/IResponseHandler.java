package eu.tneitzel.beanshooter.plugin;

import eu.tneitzel.beanshooter.exceptions.PluginException;

/**
 * The IResponseHandler interface is used during beanshooter's invoke action to handle the return value of an invoked method.
 * Implementors are expected to implement the handleResponse method that is called with the return object obtained by the
 * server.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IResponseHandler
{
    void handleResponse(Object responseObject) throws PluginException;
}
