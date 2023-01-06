package de.qtc.beanshooter.server;

import java.io.IOException;
import java.rmi.AlreadyBoundException;
import java.rmi.RemoteException;
import java.rmi.registry.LocateRegistry;
import java.security.NoSuchAlgorithmException;

import de.qtc.beanshooter.server.jmxmp.PlainJmxmpServer;
import de.qtc.beanshooter.server.jmxmp.SaslCramJmxmpServer;
import de.qtc.beanshooter.server.jmxmp.SaslDigestJmxmpServer;
import de.qtc.beanshooter.server.jmxmp.SaslNtlmJmxmpServer;
import de.qtc.beanshooter.server.jmxmp.SaslPlainJmxmpServer;
import de.qtc.beanshooter.server.jmxmp.SslJmxmpServer;
import de.qtc.beanshooter.server.rmi.PlainJmxConnector;
import de.qtc.beanshooter.server.rmi.SslJmxConnector;
import de.qtc.beanshooter.server.utils.Logger;

/**
 * The starter class contains the main function for the JMX example server and
 * is responsible for launching the different kinds of JMX services.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class Starter {

    private final static int registryPort = 9010;
    private final static int sslRegistryPort = 1090;

    private final static int jmxmpPlain = 4444;
    private final static int jmxmpSaslTLS = 4445;
    private final static int jmxmpSaslPlain = 4446;
    private final static int jmxmpSaslDigest = 4447;
    private final static int jmxmpSaslCram = 4448;
    private final static int jmxmpSaslNtlm = 4449;


    /**
     * Start the different JMX and JMXMP services.
     *
     * @param args command line arguments. None are expected.
     * @throws AlreadyBoundException Should never occur
     * @throws IOException
     */
    public static void main(String[] args) throws AlreadyBoundException, IOException
    {
       try
       {
           createRmiRegistries(registryPort, sslRegistryPort);
           createRmiBasedJmx(registryPort, sslRegistryPort);
           createJmxmpBasedJmx(jmxmpPlain, jmxmpSaslTLS, jmxmpSaslPlain, jmxmpSaslDigest, jmxmpSaslCram, jmxmpSaslNtlm);
       }
       catch( Exception e )
       {
           Logger.eprintlnYellow("Unexpected Exception:");
           e.printStackTrace();
       }
    }

    /**
     * Creates two RMI registries on different ports. The argument names may lead to the assumption
     * that one of the registries will be TLS protected, but this is not the case. Instead, this registry
     * will bind a TLS protected listener.
     *
     * @param plainPort port to start the RMI registry for the plain JMX object
     * @param sslPort port to start the RMI registry for the TLS protected JMX object
     * @throws RemoteException
     */
    private static void createRmiRegistries(int plainPort, int sslPort) throws RemoteException
    {
        Logger.printlnBlue("Creating RMI registries:");
        Logger.increaseIndent();

        Logger.printlnMixedYellow("Creating RMI registry on port", String.valueOf(plainPort));
        LocateRegistry.createRegistry(plainPort);

        Logger.printlnMixedYellow("Creating RMI registry on port", String.valueOf(sslPort));
        LocateRegistry.createRegistry(sslPort);

        Logger.decreaseIndent();
        Logger.lineBreak();
    }

    /**
     * Binds JMX services to the specified registry ports.
     *
     * @param plainPort port to bind the plain JMX service to
     * @param sslPort port to bind the TLS protected JMX object to
     * @throws IOException
     */
    public static void createRmiBasedJmx(int plainPort, int sslPort) throws IOException
    {
        Logger.printlnBlue("Creating RMI based JMX instacnes:");
        Logger.increaseIndent();

        Logger.printMixedBlue("Binding", "plain JMX", "remote object to registry on port ");
        Logger.printlnPlainYellow(String.valueOf(plainPort));

        PlainJmxConnector jmxConnector = new PlainJmxConnector(plainPort);
        jmxConnector.start();

        Logger.printMixedBlue("Binding", "SSL JMX", "remote object to registry on port ");
        Logger.printlnPlainYellow(String.valueOf(sslPort));

        SslJmxConnector sslJmxConnector = new SslJmxConnector(sslPort);
        sslJmxConnector.start();

        Logger.decreaseIndent();
        Logger.lineBreak();
    }

    /**
     * Open the different JMXMP listeners.
     *
     * @param plain port for the plain listener (noauth)
     * @param tls port for the TLS listener (noauth)
     * @param sasl port for the SASL PLAIN auth mechanism
     * @param digest port for the DIGEST-MD5 auth mechanism
     * @param cram port for the CRAM-MD5 auth mechanism
     * @param ntlm port for the NTLM auth mechanism
     * @throws NoSuchAlgorithmException
     * @throws IOException
     */
    private static void createJmxmpBasedJmx(int plain, int tls, int sasl, int digest, int cram, int ntlm) throws NoSuchAlgorithmException, IOException
    {
         Logger.printlnBlue("Creating JMXMP instances:");
         Logger.increaseIndent();

         Logger.printMixedBlue("Creating", "plain JMXMP", "server on port ");
         Logger.printlnPlainYellow(String.valueOf(plain));

         PlainJmxmpServer plainJmxmpServer = new PlainJmxmpServer(plain);
         plainJmxmpServer.start();

         Logger.printMixedBlue("Creating", "TLS JMXMP", "server on port ");
         Logger.printlnPlainYellow(String.valueOf(tls));

         SslJmxmpServer sslJmxmpServer = new SslJmxmpServer(tls);
         sslJmxmpServer.start();

         Logger.printMixedBlue("Creating", "SASL Plain JMXMP", "server on port ");
         Logger.printlnPlainYellow(String.valueOf(sasl));

         SaslPlainJmxmpServer saslPlainServer = new SaslPlainJmxmpServer(sasl);
         saslPlainServer.start();

         Logger.printMixedBlue("Creating", "SASL Digest JMXMP", "server on port ");
         Logger.printlnPlainYellow(String.valueOf(digest));

         SaslDigestJmxmpServer saslDigestServer = new SaslDigestJmxmpServer(digest);
         saslDigestServer.start();

         Logger.printMixedBlue("Creating", "SASL CRAM JMXMP", "server on port ");
         Logger.printlnPlainYellow(String.valueOf(cram));

         SaslCramJmxmpServer saslCramServer = new SaslCramJmxmpServer(cram);
         saslCramServer.start();

         Logger.printMixedBlue("Creating", "SASL NTLM JMXMP", "server on port ");
         Logger.printlnPlainYellow(String.valueOf(ntlm));

         SaslNtlmJmxmpServer saslNtlmServer = new SaslNtlmJmxmpServer(ntlm);
         saslNtlmServer.start();

         Logger.decreaseIndent();
    }
}
