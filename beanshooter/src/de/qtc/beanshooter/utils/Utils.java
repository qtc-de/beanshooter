package de.qtc.beanshooter.utils;

import java.lang.reflect.Constructor;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.UID;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;

/**
 * The Utils class contains different util functions that are used within beanshooter.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Utils {

    /**
     * Just a wrapper around System.exit(1) that prints an information before quitting.
     */
    public static void exit()
    {
        Logger.eprintln("Cannot continue from here.");
        System.exit(1);
    }

    /**
     * Parses an ObjID from a String. You can just specify a number like 1, 2 or 3 to target one of the
     * well known RMI components or a full ObjID string to target a different RemoteObject. Full ObjID
     * strings look usually like this: [196e60b8:17ac2551248:-7ffc, -7934078052539650836]
     *
     * @param objIdString Either a plain number or an ObjID value formatted as String
     * @return ObjID object constructed from the specified input string
     */
    public static ObjID parseObjID(String objIdString)
    {
        ObjID returnValue = null;

        if( !objIdString.contains(":") ) {

            try {
                long objNum = Long.parseLong(objIdString);
                return new ObjID((int)objNum);

            } catch( java.lang.NumberFormatException e ) {
                ExceptionHandler.invalidObjectId(objIdString);
            }
        }

        Pattern pattern = Pattern.compile("\\[([0-9a-f-]+):([0-9a-f-]+):([0-9a-f-]+), ([0-9-]+)\\]");
        Matcher matcher = pattern.matcher(objIdString);

        if( !matcher.find() )
            ExceptionHandler.invalidObjectId(objIdString);

        try {
            Constructor<UID> conUID = UID.class.getDeclaredConstructor(int.class, long.class, short.class);
            Constructor<ObjID> conObjID = ObjID.class.getDeclaredConstructor(long.class, UID.class);

            int unique = Integer.parseInt(matcher.group(1), 16);
            long time = Long.parseLong(matcher.group(2), 16);
            short count = (short)Integer.parseInt(matcher.group(3), 16);
            long objNum = Long.parseLong(matcher.group(4));

            conUID.setAccessible(true);
            UID uid = conUID.newInstance(unique, time, count);

            conObjID.setAccessible(true);
            returnValue = conObjID.newInstance(objNum, uid);

        } catch (Exception e) {
            ExceptionHandler.invalidObjectId(objIdString);
        }

        return returnValue;
    }

    /**
     * Determines the className of an object that implements Remote. If the specified object is a Proxy,
     * the function returns the first implemented interface name that is not java.rmi.Remote.
     *
     * @param remoteObject Object to obtain the class from
     * @return Class name of the implementor or one of it's interfaces in case of a Proxy
     */
    public static String getClassName(Remote remoteObject)
    {
        if( Proxy.isProxyClass(remoteObject.getClass()) ) {

            Class<?>[] interfaces = remoteObject.getClass().getInterfaces();

            for(Class<?> intf : interfaces) {

                String intfName = intf.getName();

                if(!intfName.equals("java.rmi.Remote"))
                    return intfName;
            }
        }

        return remoteObject.getClass().getName();
    }

    /**
     * Takes an array of Remote objects and filters out the objects that implement the RMIServer interface.
     *
     * @param remotes array of objects implementing Remote
     * @return Remote objects contained in the array that implement RMIServer
     */
    public static Remote[] filterJmxEndpoints(Remote[] remotes)
    {
        List<Remote> remoteList = new ArrayList<Remote>();

        for(Remote remote : remotes) {

            String className = getClassName(remote);

            if( className.startsWith("javax.management.remote.rmi.RMIServer") )
                remoteList.add(remote);
        }

        return remoteList.toArray(new Remote[0]);
    }

    /**
     * Converts a string into an ObjectName and handles eventually occurring exceptions.
     *
     * @param name string to convert to an ObjectName.
     * @return ObjectName created from the specified String.
     */
    public static ObjectName getObjectName(String name)
    {
        ObjectName objName = null;

        try {
            objName = new ObjectName(name);

        } catch (MalformedObjectNameException e) {
            Logger.eprintlnMixedYellow("The specified ObjectName", name, "is invalid.");
            exit();
        }

        return objName;
    }

    /**
     * Parses an URL from the specified string and handles eventually occurring exceptions.
     *
     * @param urlString string to parse the URL from.
     * @return parsed URL
     */
    public static URL parseUrl(String urlString)
    {
        URL url = null;

        try {
            url = new URL(urlString);

        } catch (MalformedURLException e) {
            Logger.eprintlnMixedYellow("The specified URL", urlString, "is invalid.");
            exit();
        }

        return url;
    }

    /**
     * Determines whether the specified host represents a local address.
     *
     * @param host address to check for
     * @return true if the specified host is a local address, false otherwise
     */
    public static boolean isLocal(String host)
    {
        InetAddress addr = null;

        try {
            addr = InetAddress.getByName(host);

            if (!addr.isAnyLocalAddress() && !addr.isLoopbackAddress())
                NetworkInterface.getByInetAddress(addr);

        } catch (UnknownHostException e) {
            Logger.eprintlnMixedYellow("The specified hostname", host, "could not be resolved.");
            exit();

        } catch (SocketException e) {
            return false;
        }

        return true;
    }

    /**
     * Compute the md5sum of an byte array.
     *
     * @param content byte array to compute the md5sum from
     * @return md5sum in hex format
     */
    public static String md5sum(byte[] content)
    {
        MessageDigest md = null;

        try {
            md = MessageDigest.getInstance("MD5");

        } catch (NoSuchAlgorithmException e) {
            ExceptionHandler.internalError("Utils.md5sum", "Unsupported Hash Algorithm");
            exit();
        }

        return bytesToHex(md.digest(content));
    }

    /**
     * Converts a byte array into a hex string. Copied from:
     * https://stackoverflow.com/questions/15429257/how-to-convert-byte-array-to-hexstring-in-java
     *
     * @param in byte array to convert
     * @return hex string representing the byte array
     */
    public static String bytesToHex(byte[] in)
    {
        final StringBuilder builder = new StringBuilder();

        for (byte b : in) {
            builder.append(String.format("%02x", b));
        }

        return builder.toString();
    }
}