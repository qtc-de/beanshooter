package de.qtc.beanshooter.plugin;

/**
 * The IArgumentProvider interface is used during beanshooters 'invoke' action to obtain the argument array that should
 * be used for the call. Plugins can implement this class to obtain custom argument arrays that they want to use during
 * the 'invoke' operation. The getArgumentArray method is called with the user specified argument string and is expected
 * to return the Object array that should be used for the call.
 *
 * This interface is implemented by beanshooters ArgumentProvider class.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public interface IArgumentProvider
{
    Object[] getArgumentArray(String argumentString);
}
