package de.qtc.beanshooter.utils;

import java.io.Serializable;

/**
 * When performing deserialization attacks, beanshooter usually sends a payload of type Object[].
 * The first item in the Object[] array is the actual gadget object. The second type is the
 * DeserializationCanary. Since deserialization of array types occurs one by one, this can be used
 * to detect whether the gadget class was accepted by the server.
 *
 *     1. If an error occurs while deserialization of the gadget class, the DeserializationCanary
 *     is never attempted to be deserialized and we obtain the exception that was thrown while
 *     deserializing the gadget class.
 *
 *  2. If the gadget class was deserialized successfully, the DeserializationCanary is loaded
 *     and throws an ClassNotFoundException that we can detect on the client side.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DeserializationCanary implements Serializable {

    private static final long serialVersionUID = 4091744402596907989L;
}
