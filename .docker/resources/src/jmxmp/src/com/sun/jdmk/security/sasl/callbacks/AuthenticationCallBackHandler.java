package com.sun.jdmk.security.sasl.callbacks;

import java.io.IOException;
import java.util.HashMap;

import javax.management.remote.extension.JMXMPSaslLifecycleListener;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthorizeCallback;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import com.sun.jdmk.security.sasl.AuthenticateCallback;

public class AuthenticationCallBackHandler implements CallbackHandler {
	
	private HashMap<String,String> credentials = new HashMap<String,String>();
	private static final Log log = LogFactory.getLog(JMXMPSaslLifecycleListener.class);
	
	public AuthenticationCallBackHandler() {
		 this.credentials.put("controlRole", "control");
		 this.credentials.put("monitorRole", "monitor");
	}

	@Override
	public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
	
	    AuthorizeCallback authorize = null;
	    AuthenticateCallback authenticate = null;
	
	    for (int i = 0; i < callbacks.length; i++) {    
	    	
	        if (callbacks[i] instanceof AuthorizeCallback) {
	        	
	        	authorize = (AuthorizeCallback)callbacks[i];

		        String authid = authorize.getAuthenticationID();
		        String authzid = authorize.getAuthorizationID();

                log.debug("Got AuthorizeCallback for '" + authid + ":" + authzid + "'");

		        if (authid.equals(authzid)) {
		        	authorize.setAuthorized(true);
		        }
	            
	        } else if (callbacks[i] instanceof AuthenticateCallback) {
	        	
	        	authenticate = (AuthenticateCallback)callbacks[i];

		        String username = authenticate.getAuthenticationID();
		        String password = new String(authenticate.getPassword());
		        String pw = credentials.get(username);

                log.debug("Got AuthenticatedCallback for '" + username + ":" + password + "'");
		
	            if(pw.equals(password)){
	            	authenticate.setAuthenticated(true);
	            }
		        
	        } else {
	            throw new UnsupportedCallbackException(callbacks[i]);
	        }
	    }
	}
} 
