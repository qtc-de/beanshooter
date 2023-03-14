package de.qtc.beanshooter.utils;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.Serializable;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.rmi.Remote;
import java.rmi.server.ObjID;
import java.rmi.server.RemoteObject;
import java.rmi.server.RemoteObjectInvocationHandler;
import java.rmi.server.RemoteRef;
import java.rmi.server.UID;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.management.Descriptor;
import javax.management.ImmutableDescriptor;
import javax.management.MBeanOperationInfo;
import javax.management.MBeanParameterInfo;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.modelmbean.ModelMBeanOperationInfo;
import javax.management.modelmbean.RequiredModelMBean;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.PluginSystem;
import sun.rmi.server.UnicastRef;
import sun.rmi.transport.LiveRef;
import sun.rmi.transport.tcp.TCPEndpoint;

/**
 * The Utils class contains different util functions that are used within beanshooter.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
@SuppressWarnings("restriction")
public class Utils {

    private static Pattern splitSpaces = Pattern.compile(" (?=(?:(?:[^'\"]*\"[^\"]*\")|(?:[^\"']*'[^']*'))*[^\"']*$)");
    private static Pattern envVariable = Pattern.compile("[a-zA-Z0-9_-]+\\=.+");

    /**
     * Just a wrapper around System.exit(1) that prints an information before quitting.
     */
    public static void exit()
    {
        Logger.eprintln("Cannot continue from here.");
        System.exit(1);
    }

    /**
     * Just a wrapper around System.exit(1) that prints an information before quitting. This
     * version is invoked with a boolean that decides whether the exit should be performed.
     *
     * @param exit whether to exit
     */
    public static void exit(boolean exit)
    {
        if(!exit)
            return;

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
     * Takes a Map of boundName - Remote mappings and filters the map for JMX endpoints.
     *
     * @param mappings  boundName - Remote mappings
     * @return Filtered map that only contains elements belonging to JMX endpoints
     */
    public static Map<String, Remote> filterJmxEndpoints(Map<String, Remote> mappings)
    {
        Map<String, Remote> filteredMap = new HashMap<String, Remote>();

        for (Map.Entry<String, Remote> entry : mappings.entrySet())
        {
            String className = getClassName(entry.getValue());

            if( className.startsWith("javax.management.remote.rmi.RMIServer") )
                filteredMap.put(entry.getKey(), entry.getValue());
        }

        return filteredMap;
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

        if(name.equals("random") || name.isEmpty())
        {
            String[] randomStuff = UUID.randomUUID().toString().split("-");
            name = String.format("%s:%s=%s", randomStuff[0], randomStuff[1], randomStuff[2]);
        }

        try {
            objName = new ObjectName(name);

        } catch (MalformedObjectNameException e) {
            Logger.eprintlnMixedYellow("The specified ObjectName", name, "is invalid.");
            Logger.eprintlnMixedBlue("Valid ObjectNames look like this:", "de.qtc.beanshooter:version=1");
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
        try {
            InetAddress addr = InetAddress.getByName(host);

            if( addr.isLoopbackAddress() )
                return true;

            else if ( addr.isAnyLocalAddress() ) {

                if( host.equals("0.0.0.0") )
                    return true;

                return false;

            } else {
                NetworkInterface intf = NetworkInterface.getByInetAddress(addr);

                if( intf != null )
                    return true;
            }

        } catch (UnknownHostException e) {
            Logger.eprintlnMixedYellow("The specified hostname", host, "could not be resolved.");
            exit();

        } catch (SocketException e) {
            return false;
        }

        return false;
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

    /**
     * Split a user specified input string on all spaces that are not contained inside quotes. For each
     * split token, remove surrounding quotes if present.
     *
     * @param input user specified input string
     * @param requiredCount minimum required count of split results
     * @return splitted string as an array
     */
    public static String[] splitSpaces(String input, int requiredCount)
    {
        String[] splitResult = splitSpaces.split(input);

        if(splitResult.length < requiredCount)
        {
            Logger.eprintlnYellow("Error: Insufficient number of arguments or unbalanced number of quotes.");
            return null;
        }

        for(int ctr = 0; ctr < splitResult.length; ctr++)
            splitResult[ctr] = Utils.stripQuotes(splitResult[ctr]);

        return splitResult;
    }

    /**
     * Helper function that reads a file into a byte array.
     *
     * @param file the file to read
     * @return content of the file as byte array
     * @throws IOException
     */
    public static byte[] readFile(String path) throws IOException
    {
        return readFile(new File(path));
    }

    /**
     * Helper function that reads a file into a byte array.
     *
     * @param file the file to read
     * @return content of the file as byte array
     * @throws IOException
     */
    public static byte[] readFile(File file) throws IOException
    {
        return Files.readAllBytes(file.toPath());
    }

    /**
     * beanshooter allows users to set environment variables during certain functionalities. This function
     * is responsible for parsing them. It takes a string, splits it on spaces (quote aware) and searches for
     * tokens with A=B format. On finding such tokens, it splits them on the "=" sign and assigns the resulting
     * key-value pair to a HashMap. This Map is returned as the parsed environment.
     *
     * @param envString user specified environment string
     * @return Map representing the environment varibales
     */
    public static Map<String,String> parseEnvironmentString(String envString)
    {
        HashMap<String,String> env = new HashMap<String,String>();

        String[] parts = Utils.splitSpaces(envString, 1);

        for(String token : parts)
        {
            if( envVariable.matcher(token).matches() )
            {
                String[] split = token.split("\\=", 2);
                env.put(split[0], Utils.stripQuotes(split[1]));
            }
        }

        return env;
    }

    /**
     * Takes an array of Classes and converts it in an array if Strings, where each String represents
     * the name of one of the input classes. This is required for MBeanServerConnection method invocation,
     * which expects the argument types as an array of String.
     *
     * @param types array of Classes to convert
     * @return String array containing the names of the classes
     */
    public static String[] typesToString(Class<?>[] types)
    {
        String[] typeNames = new String[types.length];

        for(int ctr = 0; ctr < types.length; ctr++)
            typeNames[ctr] = types[ctr].getName();

        return typeNames;
    }

    /**
     * Expand special variables within of user specified file system paths. Currently, only ~ at the
     * beginning of the path is expanded to the current users home directory. In future, we may add
     * additional expansions.
     *
     * @param path file system path to expand
     * @return expanded path
     */
    public static String expandPath(String path)
    {
        return path.replaceFirst("^~", System.getProperty("user.home"));
    }

    /**
     * Strip the leading and trailing quote from the specified input string. This modification
     * is only applied if both quotes are present.
     *
     * @param input string to apply the modification on
     * @return the modified string - or the input string if the quotes weren't present
     */
    public static String stripQuotes(String input)
    {
        if( ((input.startsWith("\"") && input.endsWith("\"")) || (input.startsWith("'") && input.endsWith("'"))) && input.length() != 1 )
            return input.substring(1, input.length() - 1);

        return input;
    }

    /**
     * Divide a Set into n separate Sets, where n is the number specified within the count argument.
     * Basically copied from: https://stackoverflow.com/questions/16449644/how-can-i-take-a-java-set-of-size-x-and-break-into-x-y-sets
     *
     * @param <T>
     * @param original Set that should be divided
     * @param count number of Sets to divide into
     * @return list of n separate sets, where n is equal to count
     */
    public static <T> List<Set<T>> splitSet(Set<T> original, int count)
    {
        ArrayList<Set<T>> result = new ArrayList<Set<T>>(count);
        Iterator<T> it = original.iterator();

        int each = original.size() / count;

        for (int i = 0; i < count; i++) {

            HashSet<T> s = new HashSet<T>(original.size() / count + 1);
            result.add(s);

            for (int j = 0; j < each && it.hasNext(); j++) {
                s.add(it.next());
            }
        }

        for(int i = 0; i < count && it.hasNext(); i++) {
            result.get(i).add(it.next());
        }

        return result;
    }

    /**
     * This code was copied from the following link and is just used to disable the annoying reflection warnings:
     *
     * https://stackoverflow.com/questions/46454995/how-to-hide-warning-illegal-reflective-access-in-java-9-without-jvm-argument
     */
    public static void disableWarning()
    {
        try {
            Field theUnsafe = sun.misc.Unsafe.class.getDeclaredField("theUnsafe");
            theUnsafe.setAccessible(true);
            sun.misc.Unsafe u = (sun.misc.Unsafe) theUnsafe.get(null);

            Class<?> cls = Class.forName("jdk.internal.module.IllegalAccessLogger");
            Field logger = cls.getDeclaredField("logger");
            u.putObjectVolatile(cls, u.staticFieldOffset(logger), null);
        } catch (Exception e) {}
    }

    /**
     * Removes the return value from a function and replaces it with void.
     *
     * @param signature user specified function signature
     * @return function signature with void as return type
     */
    public static String makeVoid(String signature)
    {
        signature = signature.trim();
        signature = signature.replaceAll(" *\\(", "(");

        int functionStart = signature.indexOf(' ');
        int argumentsStart = signature.indexOf('(');

        if (functionStart > 0 && functionStart < argumentsStart)
            signature = signature.substring(functionStart);

        return "void " + signature;
    }

    /**
     * Joins two paths. If the second specified path is an absolute path, it is returned instead
     * of being joined.
     *
     * @param first  first path to join the second with
     * @param second  second path to join
     * @return joined path, or second if absolute
     */
    public static Path joinIfRelative(String first, String second)
    {
        File secondPath = new File(second);

        if (secondPath.isAbsolute())
            return secondPath.toPath();

        return Paths.get(first, second);
    }

    /**
     * Obtain a simple signature string for the specified Method. This method exists, because the default
     * signature that can be obtained from a Method object is to verbose.
     *
     * @param m  method to obtain the signature from
     * @return method signature as string
     */
    public static String getMethodString(Method m)
    {
        StringBuilder sb = new StringBuilder();

        sb.append(m.getName());
        sb.append("(");

        if (m.getParameterCount() != 0)
        {
            for (Class<?> cc : m.getParameterTypes())
            {
                sb.append(cc.getName());
                sb.append(", ");
            }

            sb.setLength(sb.length() - 2);
        }

        sb.append(")");
        return sb.toString();
    }

    /**
     * Obtain a method signature as string from an MBeanOperationInfo object.
     *
     * @param info  MBeanOperationInfo object
     * @return method signature as string
     */
    public static String getMethodString(MBeanOperationInfo info)
    {
        StringBuilder sb = new StringBuilder();

        sb.append(info.getReturnType());
        sb.append(" ");
        sb.append(info.getName());
        sb.append("(");

        if (info.getSignature().length != 0)
        {
            for (MBeanParameterInfo cc : info.getSignature())
            {
                sb.append(cc.getType() + " " + cc.getName());
                sb.append(", ");
            }

            sb.setLength(sb.length() - 2);
        }

        sb.append(")");
        return sb.toString();
    }

    /**
     * Asks the user whether execution should continue. If the user does not confirm, the program
     * is shutdown.
     */
    public static void askToContinue(String message, Exception e)
    {
        @SuppressWarnings("resource")
        Scanner scanner = new Scanner(System.in);

        while (true)
        {
            Logger.printMixedYellow(message, "(Y/n/trace)", "");
            String input = scanner.nextLine().toLowerCase();

            switch(input)
            {
                case "":
                case "y":
                case "yes":
                    Logger.lineBreak();
                    return;

                case "t":
                case "trace":
                case "stacktrace":
                    ExceptionHandler.stackTrace(e);
                    continue;

                case "n":
                case "no":
                    Utils.exit();

                default:
                    Logger.printlnRed("Invalid choice.");
                    continue;
            }
        }
    }

    /**
     * Obtain the target endpoint from a JMX Remote object and return it as String (host:port format).
     *
     * @param remote  Remote object belonging to a JMX server
     * @return the target JMX server address in host:port format
     * @throws several reflection related exceptions
     */
    public static String getJmxTarget(Remote remote) throws IllegalArgumentException, IllegalAccessException, NoSuchFieldException, SecurityException
    {
        Field proxyField = null;
        Field remoteField = null;
        RemoteRef remoteRef = null;

        try {
            proxyField = Proxy.class.getDeclaredField("h");
            remoteField = RemoteObject.class.getDeclaredField("ref");
            proxyField.setAccessible(true);
            remoteField.setAccessible(true);

        } catch(NoSuchFieldException | SecurityException e) {
            ExceptionHandler.unexpectedException(e, "reflective access in", "extractRef", true);
        }

        if( Proxy.isProxyClass(remote.getClass()) )
            remoteRef = ((RemoteObjectInvocationHandler)proxyField.get(remote)).getRef();

        else
            remoteRef = (RemoteRef)remoteField.get(remote);

        if (!(remoteRef instanceof UnicastRef))
            return "";

        UnicastRef uref = (UnicastRef)remoteRef;
        LiveRef lref = uref.getLiveRef();

        Field endpointField = LiveRef.class.getDeclaredField("ep");
        endpointField.setAccessible(true);

        TCPEndpoint endpoint = (TCPEndpoint)endpointField.get(lref);

        String host = endpoint.getHost();
        int port = endpoint.getPort();

        return String.format("%s:%d", host, port);
    }

    /**
     * Create an array of ModelMBeanOperationInfo from the specified class. This method uses reflection to
     * determine all the available methods within the specified class, filters methods with non serializable
     * parameters and wraps each method into an ModelMBeanOperationInfo.
     *
     * @param cls  Class to obtain ModelMBeanOperationInfos from
     * @return Array of ModelMBeanOperationInfo for the specified class
     */
    public static ModelMBeanOperationInfo[] createModelMBeanInfosFromClass(Class<?> cls)
    {
        Method[] methods = cls.getMethods();
        List<ModelMBeanOperationInfo> infos = new ArrayList<ModelMBeanOperationInfo>();;

        Map<String, Object> descriptorFields = new HashMap<String, Object>();
        descriptorFields.put("class", cls.getName());
        descriptorFields.put("role", "operation");
        descriptorFields.put("descriptorType", "operation");

        outer:
        for (Method method : methods)
        {
            if (!BeanshooterOption.MODEL_ALL_METHODS.getBool())
            {
                for (Class<?> paramType : method.getParameterTypes())
                {
                    if (!(Serializable.class.isAssignableFrom(paramType)))
                        continue outer;
                }
            }

            descriptorFields.put("name", method.getName());
            descriptorFields.put("displayName", method.getName());

            Descriptor methodDescriptor = new ImmutableDescriptor(descriptorFields);
            ModelMBeanOperationInfo info = new ModelMBeanOperationInfo(method.getName(), method, methodDescriptor);

            infos.add(info);
        }

        try
        {
            Method setManagedResource = RequiredModelMBean.class.getMethod("setManagedResource", new Class[] {Object.class, String.class});
            ModelMBeanOperationInfo info = new ModelMBeanOperationInfo("setManagedResource", setManagedResource);
            infos.add(info);
        }

        catch (NoSuchMethodException | SecurityException e)
        {
            ExceptionHandler.internalError("createModelMBeanInfosFromClass", "unable to find setManagedResource method");
        }

        return infos.toArray(new ModelMBeanOperationInfo[0]);
    }

    public static ModelMBeanOperationInfo[] createModelMBeanInfosFromArg(String className)
    {
        List<ModelMBeanOperationInfo> operationInfos = new ArrayList<ModelMBeanOperationInfo>();

        if (BeanshooterOption.MODEL_SIGNATURE.notNull())
        {
            ModelMBeanOperationInfo operationInfo = crateModelMBeanInfoFromString(className, BeanshooterOption.MODEL_SIGNATURE.getValue());
            operationInfos.add(operationInfo);
        }

        else if (BeanshooterOption.MODEL_SIGNATURE_FILE.notNull())
        {
            try (BufferedReader br = new BufferedReader(new FileReader(BeanshooterOption.MODEL_SIGNATURE_FILE.<String>getValue())))
            {
                String line;

                while ((line = br.readLine()) != null)
                {
                    ModelMBeanOperationInfo operationInfo = crateModelMBeanInfoFromString(className, line);
                    operationInfos.add(operationInfo);
                }
            }

            catch (FileNotFoundException e)
            {
                Logger.printlnMixedYellow("Caught unexpected", "FileNotFoundException", "while preparing method signatures.");
                Logger.printlnMixedBlue("The specified input file", BeanshooterOption.MODEL_SIGNATURE_FILE.getValue(), "seems not to exist.");
                Utils.exit();
            }

            catch (IOException e)
            {
                ExceptionHandler.handleFileRead(e, BeanshooterOption.MODEL_SIGNATURE_FILE.getValue(), true);
            }
        }

        else
        {
            ExceptionHandler.internalError("createModelMBeanInfosFromArg", "Method was called but neither --signature nor --signature file was specified");
        }

        try
        {
            Method setManagedResource = RequiredModelMBean.class.getMethod("setManagedResource", new Class[] {Object.class, String.class});
            ModelMBeanOperationInfo info = new ModelMBeanOperationInfo("setManagedResource", setManagedResource);
            operationInfos.add(info);
        }

        catch (NoSuchMethodException | SecurityException e)
        {
            ExceptionHandler.internalError("createModelMBeanInfosFromClass", "unable to find setManagedResource method");
        }

        return operationInfos.toArray(new ModelMBeanOperationInfo[0]);
    }

    public static ModelMBeanOperationInfo crateModelMBeanInfoFromString(String className, String method)
    {
        String[] methodDesc = PluginSystem.getArgumentTypes(method, false, true);

        Map<String, Object> descriptorFields = new HashMap<String, Object>();
        descriptorFields.put("name", methodDesc[0]);
        descriptorFields.put("displayName", methodDesc[0]);
        descriptorFields.put("class", className);
        descriptorFields.put("role", "operation");
        descriptorFields.put("descriptorType", "operation");

        Descriptor methodDescriptor = new ImmutableDescriptor(descriptorFields);
        MBeanParameterInfo[] paramInfos = new MBeanParameterInfo[methodDesc.length - 1];

        for (int ctr = 1; ctr < methodDesc.length; ctr++)
        {
            paramInfos[ctr - 1] = new MBeanParameterInfo(null, methodDesc[ctr], null);
        }

        return new ModelMBeanOperationInfo(methodDesc[0], null, paramInfos, className, MBeanOperationInfo.UNKNOWN, methodDescriptor);
    }
}
