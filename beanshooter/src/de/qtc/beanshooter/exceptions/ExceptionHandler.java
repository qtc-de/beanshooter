package de.qtc.beanshooter.exceptions;

import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jolokia.client.exception.J4pRemoteException;

import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.utils.Utils;

/**
 * The ExceptionHandler class is used to unify the exception handling. For common exception reasons,
 * the exception should be caught and the corresponding handler from this class should be called. This
 * creates unified error messages for the same underlying exception reason.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ExceptionHandler {

    /**
     * Handle errors that are caused because of the (missing) --ssl parameter. Whether or not the parameter
     * was present and which error message should be printed is checked within the function.
     */
    private static void sslOption()
    {
        if(BeanshooterOption.CONN_SSL.getBool())
        {
            Logger.eprintlnMixedBlue("You probably used", "--ssl", "on a plaintext connection?");
        }

        else
        {
            Logger.eprintMixedYellow("You can retry the operation using the", "--ssl", "or ");
            Logger.eprintlnPlainMixedYellowFirst("--jmxmp", "option.");
        }
    }

    /**
     * The internal error handler should only be called for execeptions that should never occur. E.g. parsing
     * a statically defined ObjectName that is always valid. beanshooter always quits after this handler.
     *
     * @param functionName name of the function that caused the error
     * @param message additionall error message
     */
    public static void internalError(String functionName, String message)
    {
        Logger.eprintlnMixedYellow("Internal error within the", functionName, "function.");
        Logger.eprintln(message);
        Utils.exit();
    }

    /**
     * Same as InternalError, but includes the corresponding exception. This allows better debugging using
     * the --stack-trace option.
     *
     * @param e Exception that caused the error
     * @param functionName name of the function that caused the error
     * @param exit whether or not to exit after printing the error messages
     */
    public static void internalException(Exception e, String functionName, boolean exit)
    {
        Logger.eprintMixedYellow("Internal error. Caught unexpected", e.getClass().getName(), "within the ");
        Logger.eprintlnPlainMixedBlue(functionName, "function.");
        stackTrace(e);

        if(exit)
            Utils.exit();
    }

    /**
     * This handler should be called if the underlying Exception was not expected. A common scenario is when
     * you already expect some exceptions during an action but are not sure whether you catch all cases.
     *
     * @param e Exception that was thrown
     * @param during1 description of what caused the execption (colored)
     * @param during2 Additional non colored description
     * @param exit whether or not to exit after printing the error messages
     */
    public static void unexpectedException(Throwable e, String during1, String during2, boolean exit)
    {
        Logger.eprintMixedYellow("Caught unexpected", e.getClass().getName(), "during ");
        Logger.printlnPlainMixedBlueFirst(during1, during2 + ".");
        Logger.eprintln("Please report this to improve beanshooter :)");
        stackTrace(e);

        if(exit)
            Utils.exit();
    }

    public static void unknownHost(Exception e, String host, boolean exit)
    {
        Logger.eprintlnMixedYellow("Caugth", "UnknownHostException", "during connection setup.");
        Logger.eprintlnMixedBlue("The IP address of the endpoint", host, "could not be resolved.");
        showStackTrace(e);

        if(exit)
            Utils.exit();
    }

    public static void unknownHost(Exception e)
    {
        Logger.eprintlnMixedYellow("Caugth", "UnknownHostException", "during connection setup.");
        Logger.eprintlnMixedBlue("The specified target name", "could not", "be resolved.");
        showStackTrace(e);
        Utils.exit();
    }

    public static void connectException(Exception e, String callName)
    {
        Throwable t = ExceptionHandler.getCause(e);

        if( t instanceof java.net.ConnectException ) {

            String message = t.getMessage();

            if( message.contains("Connection refused") )
                ExceptionHandler.connectionRefused(e, callName, "call");

            if( message.contains("Network is unreachable") )
                ExceptionHandler.networkUnreachable(e, callName, "call");

        } else {
            ExceptionHandler.unexpectedException(e, callName, "call", true);
        }
    }

    public static void connectIOException(Exception e, String callName)
    {
        Throwable t = ExceptionHandler.getCause(e);

        if( t instanceof java.io.EOFException ) {
            ExceptionHandler.eofException(e, callName, "call");

        } else if( t instanceof java.net.SocketTimeoutException) {
            ExceptionHandler.timeoutException(e, callName, "call");

        } else if( t instanceof java.net.NoRouteToHostException) {
            ExceptionHandler.noRouteToHost(e, callName, "call");

        } else if( t instanceof java.rmi.ConnectIOException && t.getMessage().contains("non-JRMP server")) {
            ExceptionHandler.noJRMPServer(e, callName, "call");

        } else if( t instanceof javax.net.ssl.SSLException && t.getMessage().contains("Unsupported or unrecognized SSL message")) {
            ExceptionHandler.sslError(e, callName, "call");

        } else if( t instanceof java.net.SocketException && t.getMessage().contains("Network is unreachable")) {
            ExceptionHandler.networkUnreachable(e, callName, "call");

        } else if( t instanceof java.net.SocketException && t.getMessage().contains("Connection reset")) {
            ExceptionHandler.connectionReset(e, callName, "call");

        } else {
            ExceptionHandler.unexpectedException(e, callName, "call", true);
        }
    }

    public static void connectionReset(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught", "Connection Reset", "during " + during1 + " " + during2 + ".");
        Logger.eprintMixedBlue("The specified port is probably", "not an RMI service ");
        Logger.eprintlnPlainMixedBlue("or you used a wrong", "TLS", "setting.");

        ExceptionHandler.sslOption();
        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void networkUnreachable(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caugth", "SocketException", "during " + during1 + " " + during2 + ".");
        Logger.eprintlnMixedBlue("The specified target is", "not reachable", "with your current network configuration.");
        showStackTrace(e);
        Utils.exit();
    }

    public static void connectionRefused(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "ConnectException", "during " + during1 + " " + during2 + ".");
        Logger.eprintMixedBlue("Target", "refused", "the connection.");
        Logger.printlnPlainMixedBlue(" The specified port is probably", "closed.");
        showStackTrace(e);
        Utils.exit();
    }

    public static void insufficientPermission(Exception e, String during, boolean exit)
    {
        Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), "while " + during + ".");
        Logger.eprintlnMixedBlue("The specified user has", "insufficient permission", "to perform the requested action.");

        showStackTrace(e);
        Utils.exit(exit);
    }

    public static void protectedEndpoint(Exception e, String during, boolean exit)
    {
        Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), "while " + during);
        Logger.eprintlnMixedBlue("The target endpoint uses a", "jmxremote.access", "file that prevents certain actions.");

        showStackTrace(e);
        Utils.exit(exit);
    }

    public static void sslError(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "SSLException", "during " + during1 + " " + during2 + ".");
        ExceptionHandler.sslOption();

        showStackTrace(e);
        Utils.exit();
    }

    public static void noRouteToHost(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "NoRouteToHostException", "during " + during1 + " " + during2 + ".");
        Logger.eprintln("Have you entered the correct target?");
        showStackTrace(e);
        Utils.exit();
    }

    public static void noJRMPServer(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "ConnectIOException", "during " + during1 + " " + during2 + ".");
        Logger.eprintMixedBlue("Remote endpoint is probably", "no RMI endpoint", "or uses an");
        Logger.eprintlnPlainBlue(" SSL socket.");

        ExceptionHandler.sslOption();

        showStackTrace(e);
        Utils.exit();
    }

    public static void eofException(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "EOFException", "during " + during1 + " " + during2 + ".");
        Logger.eprintlnMixedBlue("One possible reason is a missmatch in the", "TLS", "settings.");

        ExceptionHandler.sslOption();

        showStackTrace(e);
        Utils.exit();
    }

    public static void timeoutException(Exception e, String during1, String during2)
    {
        Logger.eprintlnMixedYellow("Caught", "SocketTimeoutException", "during " + during1 + " " + during2 + ".");
        Logger.eprintlnMixedBlue("The specified port is probably", "not an RMI service.");
        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void notBoundException(Exception e, String boundName)
    {
        Logger.eprintMixedYellow("Caught", "NotBoundException", "on bound name ");
        Logger.printlnPlainBlue(boundName + ".");
        Logger.eprintln("The specified bound name is not bound to the registry.");
        showStackTrace(e);
        Utils.exit();
    }

    public static void noSuchObjectException(Exception e, String object, boolean exit)
    {
        Logger.eprintlnMixedYellow("Caught", "NoSuchObjectException", "during RMI call.");
        Logger.eprintlnMixedBlue("There seems to be no", object, "object avaibale on the specified endpoint.");
        showStackTrace(e);

        if(exit)
            Utils.exit();
    }

    public static void handleInstanceNotFound(Exception e, String name)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "InstanceNotFoundException", "while calling invoke.");
        Logger.eprintlnMixedBlue("The specified MBean", name, "does probably not exist on the endpoint.");
        Utils.exit();
    }

    public static void mBeanAccessDenied(Exception e, String objname, String methodName)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "SecurityException", "during method invocation.");
        Logger.eprintMixedBlue("Insufficient permissions for calling the", methodName, "method on");
        Logger.printlnPlainMixedBlue("", objname);

        showStackTrace(e);
        Utils.exit();
    }

    public static void credentialException(Exception e)
    {
        Logger.eprintlnMixedYellow("Caught", e.getClass().getName(), "while connecting to the JMX server.");

        if( BeanshooterOption.CONN_USER.isNull() )
            Logger.eprintlnMixedBlue("You need to specify", "credentials", "to connect to this JMX server.");

        else
            Logger.eprintlnMixedBlue("The specified credentials seem to be", "invalid.");

        showStackTrace(e);
        Utils.exit();
    }

    public static void handleFileWrite(Throwable e, String path, boolean exit)
    {
        Throwable t = ExceptionHandler.getCause(e);
        String message = t.getMessage();

        if (t instanceof java.io.FileNotFoundException || t.getClass() == IOException.class)
        {
            Logger.eprintlnMixedYellow("Caught", t.getClass().getName(), "while opening output file.");

            if(message.contains("Permission denied"))
                Logger.eprintlnMixedBlue("Missing the required permissions to write to:", path);

            else if(message.contains("No such file or director"))
                Logger.eprintlnMixedBlue("The parent directory of", path, "seems not to exist.");

            else if(message.contains("Is a directory"))
                Logger.eprintlnMixedBlue("The specified path", path, "is an existing directory.");

            else if(message.contains("file exists"))
                Logger.eprintlnMixedBlue("The specified file", path, "does already exist.");

            else
                unexpectedException(e, "writing", "file", exit);
        }

        else if (t instanceof java.nio.file.AccessDeniedException)
            Logger.eprintlnMixedBlue("Missing the required permissions to write to:", path);

        else if (t instanceof java.nio.file.NoSuchFileException)
            Logger.eprintlnMixedBlue("The parent directory of", path, "seems not to exist.");

        else if (t instanceof java.nio.file.FileSystemException && t.getMessage().contains("Is a directory"))
            Logger.eprintlnMixedBlue("The specified path", path, "is an existing directory.");

        else
            unexpectedException(e, "writing", "file", exit);

        showStackTrace(e);
        Utils.exit(exit);
    }

    public static void handleFileRead(Exception e, String path, boolean exit)
    {
        Throwable t = ExceptionHandler.getCause(e);
        String message = t.getMessage();
        File file = new File(path);

        if(t instanceof java.nio.file.NoSuchFileException)
        {
            if(message.contains(file.getName()))
                Logger.eprintlnMixedBlue("The specified file", path, "seems not to exist.");

            else
                unexpectedException(e, "reading", "file", exit);
        }

        else if( t instanceof java.nio.file.AccessDeniedException)
        {
            Logger.eprintlnMixedYellow("Caught", "AccessDeniedException", "while opening input file.");
            Logger.eprintlnMixedBlue("Missing the required permissions to read file:", path);
        }

        else if(t instanceof java.io.IOException)
        {
            Logger.eprintlnMixedYellow("Caught", "IOException", "while opening input file.");

            if(message.contains("Permission denied"))
                Logger.eprintlnMixedBlue("Missing the required permissions to read file:", path);


            else if(message.contains("Is a directory"))
                Logger.eprintlnMixedBlue("The specified path", path, "is an existing directory.");

            else
                unexpectedException(e, "reading", "file", exit);
        }

        else
            unexpectedException(e, "reading", "file", exit);

        showStackTrace(e);
        Utils.exit(exit);
    }

    public static void handleMBeanGeneric(Exception e)
    {
        Throwable t = ExceptionHandler.getCause(e);

        if( t instanceof java.io.EOFException )
        {
            Logger.eprintlnMixedYellow("Caught unexpected", "EOFException", "while waiting for a server response.");
            Logger.eprintln("The server has probably terminated the connection.");
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }
    }

    public static void unsupportedCallback(Exception e)
    {
        UnsupportedCallbackException callbackException = (UnsupportedCallbackException)e;
        Callback callback = callbackException.getCallback();

        Logger.eprintlnMixedYellow("Caught", "UnsupportedCallbackException", "while authenticating to JMX.");
        Logger.eprintlnMixedBlue("The server does not support the", callback.getClass().getName(), "callback.");
        Logger.println("This is probably an implementation error on the server side. You may try a different auth method.");

        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void noSuchMethod(Exception e, String method)
    {
        String signature = BeanshooterOption.INVOKE_METHOD.getValue(method);

        Logger.eprintlnMixedYellow("A method with signature", signature, "does not exist on the endpoint.");
        Logger.eprintln("If you invoked a deployed MBean, make sure that the correct version was deployed.");
        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void noSuchAttribute(Exception e, String attr)
    {
        Logger.eprintlnMixedYellow("An attribute with name", attr, "does not exist on the endpoint.");
        Logger.eprintln("If you invoked a deployed MBean, make sure that the correct version was deployed.");
        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void handleExecException(Exception e, List<String> commandArray)
    {
        Throwable t = ExceptionHandler.getCause(e);
        String message =  t.getMessage();

        if( t instanceof IOException )
        {
            if(message.contains("error=2,"))
                Logger.eprintlnMixedYellow("Unknown command:", commandArray.get(0));

            else if(message.contains("error=13,"))
                Logger.eprintlnYellow("Permission denied.");
        }

        else
        {
            unexpectedException(e, "running", "command", true);
        }
    }

    public static void handleShellExecException(Exception e, String[] commandArray)
    {
        Throwable t = ExceptionHandler.getCause(e);
        String message =  t.getMessage();

        if( t instanceof IOException )
        {
            if(message.contains("error=2,"))
                Logger.printlnPlainMixedYellow("Unknown command:", commandArray[0]);

            else if(message.contains("error=13,"))
                Logger.printlnPlainYellow("Permission denied.");
        }

        else
        {
            Logger.printlnPlainMixedYellow("Caught unexpected", t.getClass().getName(), "while running the specified command.");
            ExceptionHandler.stackTrace(e);
        }
    }

    public static void handleSecurityException(SecurityException e) throws AuthenticationException
    {
        Throwable t = getCause(e);
        String message = t.getMessage();

        if (t instanceof java.lang.SecurityException && message.contains("Authentication credentials verification failed"))
            throw new WrongCredentialsException(e);

        if (t instanceof javax.security.auth.login.FailedLoginException && message.contains("Invalid username or password"))
            throw new WrongCredentialsException(e);

        if (t instanceof java.lang.SecurityException && message.contains("Credentials required"))
            throw new MissingCredentialsException(e);

        if (t instanceof java.lang.SecurityException && message.contains("Mismatched URI"))
            throw new MismatchedURIException(e, true);

        if (t instanceof java.lang.SecurityException && message.contains("Bad credentials"))
            throw new WrongCredentialsException(e);

        if (t instanceof java.lang.SecurityException && message.contains("Authentication required"))
            throw new MissingCredentialsException(e);

        if (t instanceof java.lang.SecurityException && message.contains("None of LM and NTLM verified"))
            throw new WrongCredentialsException(e);

        if (t instanceof java.lang.SecurityException && message.contains("Invalid credential type"))
            throw new AuthenticationException(e);

        if (t instanceof java.lang.SecurityException && message.contains("Authentication failed"))
            throw new AuthenticationException(e);

        if (t instanceof java.lang.SecurityException && message.contains("Invalid response"))

            if (message.contains("javax.security.sasl.SaslException") && BeanshooterOption.CONN_SASL.getValue().equals("cram"))
                throw new WrongCredentialsException(e);
            else
                throw new AuthenticationException(e);

        if (t instanceof java.lang.SecurityException && message.contains("digest response format violation. Mismatched response."))
            throw new WrongCredentialsException(e);

        if (t instanceof javax.security.auth.login.FailedLoginException && message.contains("login failed"))
            throw new WrongCredentialsException(e);

        throw new UnknownSecurityException(e);
    }

    public static void handleAuthenticationException(AuthenticationException e)
    {
        if (e instanceof SaslMissingException)
        {
            Logger.eprintlnMixedYellow("Caught", "SaslMissingException", "while connecting to the JMX service.");
            Logger.eprintlnMixedBlue("The sever requires a", "SASL profile (--sasl)", "to be specified.");
        }

        else if (e instanceof SaslProfileException)
        {
            Logger.eprintlnMixedYellow("Caught", "SaslProfileException", "while connecting to the JMX service.");
            Logger.eprintlnMixedBlue("The specified", "SASL profile", "does not match the server SASL profile.");

            if (BeanshooterOption.CONN_SSL.getBool())
                Logger.eprintlnMixedYellow("If you are confident that you are using the correct profile, try without the", "--ssl", "option");

            else
                Logger.eprintlnMixedYellow("If you are confident that you are using the correct profile, try to use the", "--ssl", "option");
        }

        else if (e instanceof MismatchedURIException)
        {
            Logger.eprintlnMixedYellow("Caught", "MisMatchedURIException", "while connecting to the JMX service.");
            Logger.eprintlnMixedBlue("The specified", "target host", "does not match the configured SASL host.");
        }

        else if (e instanceof ApacheKarafException)
        {
            Logger.eprintlnMixedYellow("Caught", "ApacheKarafException", "while connecting to the JMX service.");
            Logger.eprintlnMixedBlue("The targeted JMX service is probably spawned by", "Apache Karaf", "and requires authentication.");
            Logger.eprintlnMixedYellow("You can attempt to login using Apache Karaf default credentials:", "karaf:karaf");
        }

        else if (e instanceof WrongCredentialsException)
        {
            Logger.eprintlnMixedYellow("Caught", "AuthenticationException", "while connecting to the JMX service.");
            Logger.eprintlnMixedBlue("The specified credentials are most likely", "incorrect.");
        }

        else if(e instanceof UnknownSecurityException)
        {
            Logger.eprintlnMixedYellow("Caught an", "unknown SecurityException", "while connecting to the JMX service.");
            Logger.eprintlnMixedBlue("The specified credentials are most likely", "incorrect.");
            Logger.eprintlnMixedYellow("However, you may use the", "--stack-trace", "option to further investigate.");
        }

        else
        {
            Logger.eprintlnMixedYellow("Caught", "AuthenticationException", "while connecting to the JMX service.");
            Logger.eprintlnMixedBlue("The targeted JMX endpoint probably", "requires authentication.");
        }

        e.showDetails();
        ExceptionHandler.showStackTrace(e);
    }

    public static void ysoNotPresent(String location)
    {
        Logger.eprintlnMixedBlue("Unable to find ysoserial library in path", location);
        Logger.eprintlnMixedYellow("Check your configuration file or use the", "--yso", "command line parameter.");
        Utils.exit();
    }

    public static void deserialClassNotFound(ClassNotFoundException e)
    {
        if( e.getMessage().contains("DeserializationCanary") ) {
            Logger.eprintlnMixedBlue("MBeanServer attempted to deserialize the", "DeserializationCanary", "class.");
            Logger.eprintlnMixedYellow("Deserialization attack was", "probably successful.");

        } else {
            Logger.eprintlnMixedYellow("Caught", "ClassNotFoundException", "after the payload object was sent.");
            Logger.eprintlnMixedBlue("The specified gadget does probably", "not exist", "inside the classpath.");
        }

        ExceptionHandler.showStackTrace(e);
    }

    public static void invalidObjectId(String objID)
    {
        Logger.eprintlnMixedYellow("The specified ObjID", objID, "is invalid.");
        Logger.eprintlnMixedBlue("Use plain numbers to target default components:", "Registry: 0, Activator: 1, DGC: 2");
        Logger.eprintlnMixedBlue("Or the full ObjID string for other remote objects:", "[unique:time:count, objNum]");
        Utils.exit();
    }

    public static void pluginException(PluginException e)
    {
        Logger.eprintlnMixedYellow("Caught unexpected", "PluginException", "during operation.");
        Logger.eprintln("The specified plugin raised this exception to indicate an error condition.");
        Logger.eprintlnMixedBlue("Plugin error message:", e.getMessage());

        if (e.origException != null)
            showStackTrace(e.origException);

        Utils.exit();
    }

    public static void lookupClassNotFoundException(Exception e, String name)
    {
        name = name.replace(" (no security manager: RMI class loader disabled)", "");

        Logger.eprintlnMixedYellow("Caught unexpected", "ClassNotFoundException", "during lookup action.");
        Logger.eprintlnMixedBlue("The class", name, "could not be resolved within your class path.");
        Logger.eprintlnMixedBlue("You probably specified a bound name that does not implement the", "RMIServer", "interface.");

        showStackTrace(e);
        Utils.exit();
    }

    public static void ioException(Exception e, String during)
    {
        Throwable t = ExceptionHandler.getCause(e);

        if(t instanceof java.rmi.ConnectException)
            ExceptionHandler.connectException(e, during);

        else if(t instanceof java.rmi.ConnectIOException )
            ExceptionHandler.connectIOException(e, during);

        else if(t instanceof java.rmi.UnknownHostException )
            ExceptionHandler.unknownHost(e);

        else
            ExceptionHandler.unknownReason(e);
    }

    public static void handleJ4pRemoteException(J4pRemoteException e, String during)
    {
        String message = e.getMessage();

        if (message.contains("No JSR-160 proxy is enabled"))
            ExceptionHandler.noJolokiaProxy(e);

        if (message.contains("is not allowed by configuration"))
            ExceptionHandler.jolokiaDenyList(e);

        if (message.contains("Error: java.net.MalformedURLException"))
            ExceptionHandler.jolokiaMalformedUrl(e);

        if (message.contains("createMBean not supported"))
            ExceptionHandler.jolokiaCreateMBean(e);

        else
            ExceptionHandler.unexpectedStatus(e, during);
    }

    public static void unexpectedStatus(J4pRemoteException e, String during)
    {
        Logger.eprintlnMixedYellow("Obtained the unexpected status code", String.valueOf(e.getStatus()), during);
        Logger.eprintlnMixedBlue("Error Message:", e.getMessage());

        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void jolokiaCreateMBean(Exception e)
    {
        Logger.eprintlnMixedYellow("Creating new MBeans", "is not", "supported by Jolokia.");
        Logger.eprintlnMixedBlue("New MBeans can only be loaded if the", "MLet MBean", "is already available.");
        Logger.eprintlnMixedYellow("If this is the case you can use beanshooters", "mlet load", "action to load new MBeans.");

        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void jolokiaRemoveMBean(Exception e)
    {
        Logger.eprintlnMixedYellow("Removing MBeans", "is not", "supported by Jolokia.");
        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void noJolokiaProxy(J4pRemoteException e)
    {
        Logger.eprintlnMixedYellow("Target server", "does not", "support Jolokia proxy mode.");
        Logger.eprintMixedBlue("Neither the", "jolokia", "action nor the ");
        Logger.eprintlnPlainMixedBlueFirst("--jolokia-proxy", "option can be used.");

        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void jolokiaDenyList(J4pRemoteException e)
    {
        Logger.eprintlnMixedYellow("The specified proxy URL", BeanshooterOption.CONN_JOLOKIA_PROXY.getValue(), "is blocked by Jolokias denylist.");
        Logger.eprintlnMixedBlue("You may be able to", "bypass", "this filter by applying simple string modifications.");

        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void jolokiaMalformedUrl(J4pRemoteException e)
    {
        String error = e.getMessage().split("MalformedURLException : ")[1];

        Logger.eprintlnMixedYellow("Jolokia", "rejected", "the specified URL.");
        Logger.eprintlnMixedBlue("Error message:", error);

        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void noOperation(Exception e, String signature)
    {
        Logger.eprintlnMixedYellow("The specified method signature", signature, "is not known by the server.");
        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void noOperationAlternative(Exception e, String signature, String method, String message)
    {
        String alternatives = message.substring(message.lastIndexOf(' ')).trim();

        Logger.eprintlnMixedYellow("The specified method signature", signature, "is not known by the server.");
        Logger.eprintMixedYellow("The following signatures are known", alternatives, "for the method ");
        Logger.eprintlnPlainBlue(method);

        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void unknownReason(Exception e, String during)
    {
        Throwable t = ExceptionHandler.getCause(e);
        Logger.eprintlnMixedYellow("Caught unexpected", t.getClass().getName(), during);

        ExceptionHandler.unknownReason(e);
    }

    public static void unknownReason(Exception e)
    {
        Logger.eprintlnMixedBlue("The exception occured unexpected and was not caught by", "beanshooter.");
        Logger.eprintln("Please report the exception to help improving the exception handling :)");
        ExceptionHandler.stackTrace(e);
        Utils.exit();
    }

    public static void invalidSignature(Throwable e, String signature)
    {
        Logger.eprintlnMixedYellow("The specified method signature", signature, "is invalid.");
        Logger.eprintlnMixedBlue("The method signature has to be a valid method signature like:", "int example(String test, int test2)");
        Logger.eprintlnMixedYellow("Make sure to use", "full qualified", "class names and that all classes are available on the classpath.");
        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void invalidArgumentException(Throwable e, String argumentString)
    {
        Logger.eprintlnMixedYellow("The specified argument string", argumentString, "is invalid.");
        Logger.eprintlnMixedBlue("Make sure to use", "full qualified", "class names and that all classes are available within the classpath.");
        ExceptionHandler.showStackTrace(e);
        Utils.exit();
    }

    public static void argumentCountMismatch(int actual, int expected)
    {
        Logger.eprintln("Mismatching number of arguments for the specified signature.");
        Logger.eprintMixedBlueFirst("Expected " + expected, "argument(s), but", "got " + actual);
        Logger.printlnPlain(" arguments.");
        Utils.exit();
    }

    public static void openTypeException(String type, String during)
    {
        Logger.printlnMixedYellow("Caught unexpected", type, "while " + during + ".");
        Logger.printlnMixedBlue("StackTrace cannot be provided as the exception was caused by an", "OpenType");
        Utils.exit();
    }

    /**
     * Walks down a stacktrace and searches for a specific exception name.
     * If it finds the corresponding name, the corresponding Throwable is returned.
     *
     * @param name Exception name to look for.
     * @param e stack trace to search in.
     * @return identified Throwable.
     */
    public static Throwable getThrowable(String name, Throwable e)
    {
        if( e.getClass().getSimpleName().equals(name) )
            return e;

        Throwable exception = e;
        Throwable cause = e.getCause();

        while((exception != cause) && (cause != null)) {

            if( cause.getClass().getSimpleName().equals(name))
                return cause;

            exception = cause;
            cause = exception.getCause();
        }

        return null;
    }

    /**
     * Taken from https://stackoverflow.com/questions/17747175/how-can-i-loop-through-exception-getcause-to-find-root-cause-with-detail-messa
     * Returns the actual cause of an exception.
     *
     * @param e Exception that should be handeled.
     * @return cause of the Exception.
     */
    public static Throwable getCause(Throwable e)
    {
        Throwable cause = null;
        Throwable result = e;

        while(null != (cause = result.getCause()) && (result != cause) ) {
            result = cause;
        }

        return result;
    }

    /**
     * By using the --stack-trace option, users can always display stack traces if they
     * want to. This is handled by this function. It checks whether --stack-trace was used
     * and prints the stacktrace if desired. This function should be used in most of the error
     * handling code of beanshooter.
     *
     * @param e Exception that was caught.
     */
    public static <T extends Throwable> void showStackTrace(T e)
    {
        if( BeanshooterOption.GLOBAL_STACK_TRACE.getBool() ) {
            Logger.eprintln("");
            stackTrace(e);
        }
    }

    /**
     * Helper function that prints a stacktrace with a prefixed Logger item.
     *
     * @param e Exception that was caught.
     */
    public static <T extends Throwable> void stackTrace(T e)
    {
        Logger.eprintln("StackTrace:");
        e.printStackTrace();
    }
}
