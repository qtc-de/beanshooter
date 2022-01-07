package de.qtc.beanshooter;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.operation.Dispatcher;
import de.qtc.beanshooter.operation.Operation;

/**
 * The Stater class handles the startup process of beanshooter. beanshooter actions
 * are invoked via reflection. This adds one additional layer of complexity but allows
 * to define available actions in an enum, which makes it more explicit what actions are
 * actually available.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Starter {

    public static void main(String[] argv)
    {
        ArgumentHandler handler = new ArgumentHandler(argv);
        Operation operation = handler.getAction();

        Dispatcher dispatcher = new Dispatcher();
        operation.invoke(dispatcher);
    }
}