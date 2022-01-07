package de.qtc.beanshooter.plugin;

import java.rmi.server.RMIClientSocketFactory;
import java.rmi.server.RMISocketFactory;

import de.qtc.beanshooter.cli.Option;
import de.qtc.beanshooter.networking.LoopbackSocketFactory;
import de.qtc.beanshooter.networking.LoopbackSslSocketFactory;
import de.qtc.beanshooter.networking.TrustAllSocketFactory;

/**
 * beanshooters default implementation for an ISocketFactoryProvider.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class DefaultSocketFactoryProvider implements ISocketFactoryProvider {

     /**
     * Returns an RMIClientSocketFactory according to the specified options on the command line.
     */
    @Override
    public RMIClientSocketFactory getClientSocketFactory()
    {
        if( Option.CONN_SSL.getBool() ) {
            return new TrustAllSocketFactory();

        } else {
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
    public RMISocketFactory getDefaultSocketFactory(String host, int port)
    {
        RMISocketFactory fac = RMISocketFactory.getDefaultSocketFactory();
        return new LoopbackSocketFactory(host, fac, Option.CONN_FOLLOW.getBool());
    }

    /**
     * The default SSLRMISocketFactory used by beanshooter is the LoopbackSslSocketFactory, which
     * redirects all connection to the original target and thus prevents unwanted RMI redirections.
     */
    @Override
    public String getDefaultSSLSocketFactory(String host, int port)
    {
        TrustAllSocketFactory trustAllFax = new TrustAllSocketFactory();

        LoopbackSslSocketFactory.host = host;
        LoopbackSslSocketFactory.fac = trustAllFax.getSSLSocketFactory();
        LoopbackSslSocketFactory.followRedirect = Option.CONN_FOLLOW.getBool();

        return "de.qtc.beanshooter.networking.LoopbackSslSocketFactory";
    }
}
