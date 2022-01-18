package de.qtc.beanshooter.plugin.providers;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.Map;

import javax.management.MBeanServerConnection;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;

import de.qtc.beanshooter.cli.ArgumentHandler;
import de.qtc.beanshooter.cli.SASLMechanism;
import de.qtc.beanshooter.exceptions.AuthenticationException;
import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.exceptions.MismatchedURIException;
import de.qtc.beanshooter.exceptions.SaslProfileException;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;
import de.qtc.beanshooter.plugin.IMBeanServerProvider;
import de.qtc.beanshooter.plugin.PluginSystem;
import de.qtc.beanshooter.utils.Utils;

/**
 * The JMXMP provider provides MBeanServerConnections by using the JMXMP protocol.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class JMXMPProvider implements IMBeanServerProvider {

    private static final String connString = "service:jmx:jmxmp://%s:%s";

    @Override
    public MBeanServerConnection getMBeanServerConnection(String host, int port, Map<String,Object> env) throws AuthenticationException  
    {
    	MBeanServerConnection mBeanServerConnection = null;
    	
        java.security.Security.setProperty("ssl.SocketFactory.provider", PluginSystem.getDefaultSSLSocketFactoryClass(host, port));

        if( BeanshooterOption.CONN_SSL.getBool() )
        {
            env.put("jmx.remote.tls.socket.factory", PluginSystem.getDefaultSSLSocketFactory(host, port));
            env.put("jmx.remote.profiles", "TLS");
        }

        SASLMechanism saslMechanism = ArgumentHandler.getSASLMechanism();
        if( saslMechanism != null )
        {
        	ArgumentHandler.requireAllOf(BeanshooterOption.CONN_USER, BeanshooterOption.CONN_PASS);
        	
        	String username = ArgumentHandler.require(BeanshooterOption.CONN_USER);
        	String password = ArgumentHandler.require(BeanshooterOption.CONN_PASS);
        	
        	saslMechanism.init(env, username, password);
        }

        try 
        {
            JMXServiceURL jmxUrl = new JMXServiceURL(String.format(connString, host, port));
            JMXConnector jmxConnector = JMXConnectorFactory.connect(jmxUrl, env);

            mBeanServerConnection = jmxConnector.getMBeanServerConnection();
        }
        
        catch (MalformedURLException e) 
        {
            ExceptionHandler.internalError("DefaultMBeanServerProvider.getMBeanServerConnection", "Invalid URL.");
        } 
        
        catch (IOException e)
        {
        	Throwable t = ExceptionHandler.getCause(e);
        	String message = t.getMessage();
        	
        	if( t instanceof IOException && message.contains("negotiated profiles do not match") )
        		throw new SaslProfileException(e, true);
        	
        	if( t instanceof IOException && message.contains("do not match the client required profiles") )
        		throw new SaslProfileException(e, true);
        	
        	if( t instanceof IOException && message.contains("not require any profile but the server mandates on") )
        		throw new SaslProfileException(e, true);

        	if( t instanceof IOException && message.contains("The server does not support any profile") )
        		throw new SaslProfileException(e, true);
        	
            Logger.eprintlnMixedYellow("Caught unexpected", "IOException", "while connecting to the specified JMX service.");
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }
        
        catch( java.lang.SecurityException e )
        {
        	Throwable t = ExceptionHandler.getCause(e);
        	String message = t.getMessage();
        	
        	if( t instanceof java.lang.SecurityException && message.contains("Authentication credentials verification failed") )
        		throw new AuthenticationException(e);
        	
        	if( t instanceof java.lang.SecurityException && message.contains("Mismatched URI") )
        		throw new MismatchedURIException(e, true);
        	
        	if( t instanceof java.lang.SecurityException && message.contains("Invalid response") )
        		throw new AuthenticationException(e);
        	
            Logger.eprintlnMixedYellow("Caught unexpected", "SecurityException", "while connecting to the specified JMX service.");
            ExceptionHandler.showStackTrace(e);
            Utils.exit();
        }

        return mBeanServerConnection;
    }

}
