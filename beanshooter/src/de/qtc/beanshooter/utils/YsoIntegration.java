package de.qtc.beanshooter.utils;

import java.io.File;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;

/**
 * Wrapper around ysoserial. Is used to validate the path to the ysoserial jar file and to create gadgets.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class YsoIntegration {

    /**
     * Just a small wrapper around the URLClassLoader creation. Checks the existence of the specified file
     * path before creating a class loader around it.
     *
     * @return URLClassLoader for ysoserial classes
     * @throws MalformedURLException when the specified file system path exists, but is invalid
     */
    private static URLClassLoader getClassLoader() throws MalformedURLException
    {
        File ysoJar = new File((String)ArgumentHandler.require(BeanshooterOption.YSO));

        if( !ysoJar.exists() ) {
            ExceptionHandler.ysoNotPresent(BeanshooterOption.YSO.getValue());
        }

        return new URLClassLoader(new URL[] {ysoJar.toURI().toURL()});
    }

    /**
     * Loads ysoserial using and separate URLClassLoader and invokes the makePayloadObject function by using
     * reflection. The result is a ysoserial gadget as it would be created on the command line.
     *
     * @param gadget name of the desired gadget
     * @param command command specification for the desired gadget
     * @return ysoserial gadget
     */
    public static Object getPayloadObject(String gadget, String command)
    {
        Object ysoPayload = null;

        try {
            URLClassLoader ucl = getClassLoader();

            Class<?> yso = Class.forName("ysoserial.payloads.ObjectPayload$Utils", true, ucl);
            Method method = yso.getDeclaredMethod("makePayloadObject", new Class[] {String.class, String.class});

            Logger.print("Creating ysoserial payload...");
            ysoPayload = method.invoke(null, new Object[] {gadget, command});

        } catch( Exception  e) {
            Logger.printlnPlain(" failed.");
            Logger.eprintlnMixedYellow("Caught unexpected", e.getClass().getName(), "during gadget generation.");
            Logger.eprintMixedBlue("You probably specified", "a wrong gadget name", "or an ");
            Logger.eprintlnPlainBlue("invalid gadget argument.");
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }

        Logger.printlnPlain(" done.");
        return ysoPayload;
    }
}
