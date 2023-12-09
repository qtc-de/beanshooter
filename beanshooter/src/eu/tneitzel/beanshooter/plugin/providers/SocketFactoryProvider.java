package eu.tneitzel.beanshooter.plugin.providers;

import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;

import javax.net.SocketFactory;

import eu.tneitzel.beanshooter.networking.LoopbackSocketFactory;
import eu.tneitzel.beanshooter.networking.LoopbackSslSocketFactory;
import eu.tneitzel.beanshooter.networking.TrustAllSocketFactory;
import eu.tneitzel.beanshooter.operation.BeanshooterOption;
import eu.tneitzel.beanshooter.plugin.ISocketFactoryProvider;

/**
 * beanshooters default implementation for an ISocketFactoryProvider.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class SocketFactoryProvider implements ISocketFactoryProvider {

     /**
     * Returns an RMIClientSocketFactory according to the specified options on the command line.
     * The factory returned by this function is aimed to be used for connections that target a
     * remote object directly. In these cases, unwanted redirects are usually not happen and we
     * do not need to use one of the Loopback factories.
     */
    @Override
    public RMIClientSocketFactory getRMIClientSocketFactory(String host, int port)
    {
        if( BeanshooterOption.CONN_SSL.getBool() )
        {
            return new TrustAllSocketFactory();
        }

        else
        {
            return RMISocketFactory.getDefaultSocketFactory();
        }
    }

    /**
     * The default RMISocketFactory used by beanshooter is the LoopbackSocketFactory, which
     * redirects all connection to the original target and thus prevents unwanted RMI redirections.
     *
     * This function is only used for 'managed' RMI calls that rely on an RMI registry. Remote objects that
     * are looked up from the RMI registry use the RMISocketFactory.getDefaultSocketFactory function to
     * obtain a SocketFactory. This factory is then used for explicit calls (method invocations) and for
     * implicit calls (DGC actions like clean or dirty).
     */
    @Override
    public RMISocketFactory getDefaultRMISocketFactory(String host, int port)
    {
        RMISocketFactory fac = RMISocketFactory.getDefaultSocketFactory();
        return new LoopbackSocketFactory(host, fac, BeanshooterOption.CONN_FOLLOW.getBool());
    }

    /**
     * The default SSLRMISocketFactory used by beanshooter is the LoopbackSslSocketFactory, which
     * redirects all connection to the original target and thus prevents unwanted RMI redirections.
     */
    @Override
    public String getDefaultSSLSocketFactoryClass(String host, int port)
    {
        TrustAllSocketFactory trustAllFax = new TrustAllSocketFactory();

        LoopbackSslSocketFactory.host = host;
        LoopbackSslSocketFactory.fac = trustAllFax.getSSLSocketFactory();
        LoopbackSslSocketFactory.followRedirect = BeanshooterOption.CONN_FOLLOW.getBool();

        return "eu.tneitzel.beanshooter.networking.LoopbackSslSocketFactory";
    }

    /**
     * Returns the socket factory that should be used for non RMI based TLS protected connections.
     * This is e.g. used by the JMXMP provider.
     */
    public SocketFactory getSSLSocketFactory(String host, int port)
    {
        return new TrustAllSocketFactory().getSSLSocketFactory();
    }
}
