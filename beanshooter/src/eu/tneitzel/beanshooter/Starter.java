package eu.tneitzel.beanshooter;

import eu.tneitzel.beanshooter.cli.ArgumentHandler;
import eu.tneitzel.beanshooter.cli.Operation;
import eu.tneitzel.beanshooter.utils.Utils;

/**
 * The Stater class handles the startup process of beanshooter. beanshooter actions
 * are invoked via reflection. This adds one additional layer of complexity but allows
 * to define available actions in an enum, which makes it more explicit what actions are
 * actually available.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Starter
{
    public static void main(String[] argv)
    {
        ArgumentHandler handler = new ArgumentHandler(argv);
        Utils.disableWarning();
        Operation operation = handler.getAction();
        operation.invoke();
    }
}
