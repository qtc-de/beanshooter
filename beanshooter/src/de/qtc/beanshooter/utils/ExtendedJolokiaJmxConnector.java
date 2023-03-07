package de.qtc.beanshooter.utils;

import java.io.IOException;
import java.net.MalformedURLException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;

import javax.management.remote.JMXServiceURL;
import javax.net.ssl.SSLContext;

import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.ssl.TrustStrategy;
import org.jolokia.client.J4pClientBuilder;
import org.jolokia.client.jmxadapter.JolokiaJmxConnector;

import de.qtc.beanshooter.exceptions.ExceptionHandler;
import de.qtc.beanshooter.io.Logger;
import de.qtc.beanshooter.operation.BeanshooterOption;

/**
 * The ExtendedJolokiaJmxConnector is a wrapper around the official JolokiaJmxConnector.
 * It extends the connect function to include support for proxy mode.
 *
 * @author Tobias Neitzel (@qtc_de)
 */
public class ExtendedJolokiaJmxConnector extends JolokiaJmxConnector
{
    private final String target;

    /**
     * Just the regular constructor with an optional target argument that represents the proxy target.
     *
     * @param serviceURL  Jolokia service URL
     * @param environment  connection variables (e.g. username and password for connecting to Jolokia)
     * @param target  target to connect to when proxy mode is used
     */
    public ExtendedJolokiaJmxConnector(JMXServiceURL serviceURL, Map<String, ?> environment, String target)
    {
        super(serviceURL, environment);

        this.target = target;
    }

    /**
     * Copy and paste from the official JolokiaJmxConnector. Just inserted the required code for
     * supporting proxy mode. Original code can be found here: https://github.com/rhuss/jolokia
     */
    public void connect(Map<String, ?> env) throws IOException
    {
        if (!"jolokia".equals(this.serviceUrl.getProtocol()))
        {
            throw new MalformedURLException(String.format("Invalid URL %s : Only protocol \"jolokia\" is supported (not %s)",  this.serviceUrl, this.serviceUrl.getProtocol()));
        }

        Map<String, Object> mergedEnv = mergedEnvironment(env);
        String internalProtocol = "http";

        if (BeanshooterOption.CONN_SSL.getBool())
            internalProtocol = "https";

        final J4pClientBuilder clientBuilder = new J4pClientBuilder().url(
                internalProtocol + "://" + this.serviceUrl.getHost() + ":" + this.serviceUrl.getPort()
                + prefixWithSlashIfNone(this.serviceUrl.getURLPath()));

        try
        {
            // Taken from: https://stackoverflow.com/a/19519566

            NoopHostnameVerifier verifier = NoopHostnameVerifier.INSTANCE;
            SSLContext ctx = SSLContexts.custom().loadTrustMaterial(new TrustStrategy()
            {
                @Override
                public boolean isTrusted(X509Certificate[] chain, String authType) throws CertificateException
                {
                    return true;
                }
             }).build();

            SSLConnectionSocketFactory facs = new SSLConnectionSocketFactory(ctx, verifier);
            clientBuilder.sslConnectionSocketFactory(facs);
        }

        catch (KeyManagementException | NoSuchAlgorithmException | KeyStoreException e)
        {
            Logger.printlnMixedYellow("Caught unexpected", e.getClass().getName(), "while setting the SSL context for Jolokia.");
            ExceptionHandler.stackTrace(e);
            Utils.exit();
        }

        if (mergedEnv.containsKey(CREDENTIALS))
        {
             String[] credentials = (String[]) mergedEnv.get(CREDENTIALS);
             clientBuilder.user(credentials[0]);
             clientBuilder.password(credentials[1]);
        }

        if (target != null)
        {
            clientBuilder.target(target);

            String proxyUser = BeanshooterOption.CONN_JOLOKIA_PROXY_USER.getValue();
            String proxyPass = BeanshooterOption.CONN_JOLOKIA_PROXY_PASS.getValue();

            if (proxyUser != null && proxyPass != null)
            {
                clientBuilder.targetUser(proxyUser);
                clientBuilder.targetPassword(proxyPass);
            }
        }

        this.adapter = instantiateAdapter(clientBuilder, mergedEnv);
        postCreateAdapter();
    }

    /**
     * Also copied from the original project at: https://github.com/rhuss/jolokia
     */
    private String prefixWithSlashIfNone(String urlPath)
    {
        if (urlPath.startsWith("/"))
          return urlPath;

        else
          return "/" + urlPath;
    }
}
