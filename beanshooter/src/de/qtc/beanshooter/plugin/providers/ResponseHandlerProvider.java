package de.qtc.beanshooter.plugin.providers;

import java.io.File;
import java.lang.reflect.Array;
import java.util.Collection;
import java.util.Map;
import java.util.Map.Entry;

import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.plugin.IResponseHandler;

/**
 * The ResponseHandlerProvider is the default response handler for beanshooter's invoke operation.
 * It performs a generic print and tries to visualize the return value of the invoke method.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ResponseHandlerProvider implements IResponseHandler {

    /**
     * The handleResponse function is called with the incoming responseObject from the
     * MBean server. Depending on the corresponding class, a different print action is
     * chosen.
     *
     * @param responseObject Incoming object from an RMI server response
     */
    public void handleResponse(Object responseObject)
    {
        Class<?> responseClass = responseObject.getClass();

        if(responseObject instanceof Collection<?>)
            handleCollection(responseObject);

        else if(responseObject instanceof Map<?,?>)
            handleMap(responseObject);

        else if(responseClass.isArray())
            handleArray(responseObject);

        else if(responseObject instanceof File)
            handleFile((File)responseObject);

        else if(responseObject instanceof Byte)
            handleByte((byte)responseObject);

        else
            handleDefault(responseObject);
    }

    /**
     * For each item within an collection, call handleResponse on the corresponding
     * item value.
     *
     * @param o Object of the Collection type
     */
    public void handleCollection(Object o)
    {
        for(Object item: (Collection<?>)o)
            handleResponse(item);
    }

    /**
     * For each entry within a map, handleResponse is called on the entry key and value.
     * Furthermore, an arrow is printed in an attempt to visualize their relationship.
     *
     * @param o Object of the Map type
     */
    public void handleMap(Object o)
    {
        Map<?,?> map = (Map<?,?>)o;

        for(Entry<?,?> item: map.entrySet()) {
            handleResponse(item.getKey());
            System.out.print("  --> ");
            handleResponse(item.getValue());
        }
    }

    /**
     * For each item within an array, call the handleResponse function.
     *
     * @param o Object of the Array type
     */
    public void handleArray(Object o)
    {
        Object[] objectArray = null;
        Class<?> type = o.getClass().getComponentType();

        if(type.isPrimitive()) {
            int length = Array.getLength(o);
            objectArray = new Object[length];
            for(int ctr = 0; ctr < length; ctr++)
                objectArray[ctr] = Array.get(o, ctr);

        } else {
            objectArray = (Object[])o;
        }

        for(Object item: objectArray)
            handleResponse(item);
    }

    /**
     * For File objects, print their absolute path.
     *
     * @param o File object
     */
    public void handleFile(File o)
    {
        Logger.printlnPlain(o.getAbsolutePath());
    }

    /**
     * Byte objects are converted to hex and printed. As a single byte is most likely part of a
     * sequence, we print without a newline.
     *
     * @param o File object
     */
    public void handleByte(byte o)
    {
        Logger.printPlain(String.format("%02x", o));
    }

    /**
     * The default action for each object is to print it using it's toString method.
     *
     * @param o Object that did not matched one of the previously mentioned types.
     */
    public void handleDefault(Object o)
    {
        Logger.printlnPlain(o.toString());
    }
}
