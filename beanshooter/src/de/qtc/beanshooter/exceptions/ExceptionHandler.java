package de.qtc.beanshooter.exceptions;

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
            Logger.eprintlnMixedBlue("You probably used", "--ssl", "on a plaintext connection?");
        else
            Logger.eprintlnMixedYellow("You can retry the operation using the", "--ssl", "option.");
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
        Logger.printlnPlainMixedBlue(functionName, "function.");
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
    public static void unexpectedException(Exception e, String during1, String during2, boolean exit)
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
        Logger.eprintMixedBlue("Remote endpoint is either", "no RMI endpoint", "or uses an");
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
    
    public static void ysoNotPresent(String location)
    {
        Logger.eprintlnMixedBlue("Unable to find ysoserial library in path", location);
        Logger.eprintlnMixedYellow("Check your configuration file or use the", "--yso", "command line parameter.");
        Utils.exit();
    }
    
    public static void deserialClassNotFound(ClassNotFoundException e)
    {
		if( e.getMessage().contains("DeserializationCanary") ) {
			Logger.printlnMixedBlue("MBeanServer attempted to deserialize the", "DeserializationCanary", "class.");
			Logger.printlnMixedYellow("Deserialization attack was", "probably successful.");
			
		} else {
            Logger.eprintlnMixedYellow("Caught", "ClassNotFoundException", "after the payload object was sent.");
            Logger.eprintlnMixedBlue("The specified gadget does probably", "not exist", "inside the classpath.");
		}
    }

    public static void invalidObjectId(String objID)
    {
        Logger.eprintlnMixedYellow("The specified ObjID", objID, "is invalid.");
        Logger.eprintlnMixedBlue("Use plain numbers to target default components:", "Registry: 0, Activator: 1, DGC: 2");
        Logger.eprintlnMixedBlue("Or the full ObjID string for other remote objects:", "[unique:time:count, objNum]");
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
    
    public static void unknownReason(Exception e, String during)
    {
		Throwable t = ExceptionHandler.getCause(e);
		Logger.printlnMixedYellow("Caught unexpected", t.getClass().getName(), during);
		
		ExceptionHandler.unknownReason(e);
    }
    
    public static void unknownReason(Exception e)
    {
    	Logger.printlnMixedBlue("The exception occured unexpected and was not caught by", "beanshooter.");
    	Logger.println("Please report the exception to help improving the exception handling :)");
    	ExceptionHandler.stackTrace(e);
    	Utils.exit();
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
