package de.qtc.beanshooter.plugin;

import de.qtc.beanshooter.exceptions.PluginException;

/**
 * The IArgumentProvider interface is used during beanshooters 'invoke' action to obtain the argument array that should
 * be used for the call. Plugins can implement this class to obtain custom argument arrays that they want to use during
 * the 'invoke' operation. The getArgumentArray method is called with the user specified argumentArray and is expected
 * to return an Object array that should be used for the call.
 *
 * When calling 'invoke', users have specify the full method signature like 'bool example(int arg1, long[] arg2)'. This
 * signature is passed to the getArgumentTypes function, which is expected to return an array of associated argument type
 * names. Such an array is required for each MBean call and additional parsing is required to create it. In the example
 * from above, the parsed argument type array would look like this: 'new String[] { "int", "[L" }'. This shows that
 * primitive types can cause problems and need to be handled with care.
 *
 * This interface is implemented by beanshooters de.qtc.beanshooter.plugin.providers.ArgumentProvider class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IArgumentProvider
{
    Object[] getArgumentArray(String[] argumentArray) throws PluginException;
    Object strToObj(String str) throws PluginException;
    String[] getArgumentTypes(String signature) throws PluginException;
    String[] getArgumentTypes(String signature, boolean includeReturn, boolean includeName) throws PluginException;
    String getMethodName(String signature) throws PluginException;
}
