/* Credits: https://github.com/felixoldenburg/jmxmp-lifecycle-listener */
package javax.management.remote.extension;

import java.lang.management.ManagementFactory;
import java.util.HashMap;

import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import com.sun.jdmk.security.sasl.callbacks.AuthenticationCallBackHandler;

public class JMXMPSaslDigestLifecycleListener implements LifecycleListener
{
    protected int port = 5558;
    protected JMXConnectorServer cs;
    private static final Log log = LogFactory.getLog(JMXMPSaslDigestLifecycleListener.class);

    public int getPort() {
        return port;
    }

    public void setPort(final int port) {
        this.port = port;
    }

    @SuppressWarnings({ "rawtypes", "unchecked" })
    @Override
    public void lifecycleEvent(final LifecycleEvent event)
    {
        try {

            if (Lifecycle.START_EVENT == event.getType()) {
                log.info("Starting JMXMP SASL Listener (Digest)");

                HashMap env = new HashMap();
                SSLContext ctx = SSLContext.getDefault();
                SSLSocketFactory ssf = ctx.getSocketFactory();

                env.put("jmx.remote.profiles", "TLS SASL/DIGEST-MD5");
                env.put("jmx.remote.sasl.callback.handler", new AuthenticationCallBackHandler());
                env.put("jmx.remote.x.access.file", "/opt/jmxmp.access");
                env.put("jmx.remote.tls.socket.factory", ssf); 

                /* Somehow the next option is not accepted :/ */
                env.put("com.sun.security.sasl.digest.realm", "iinsecure.dev");

                cs = JMXConnectorServerFactory.newJMXConnectorServer(
                    new JMXServiceURL("jmxmp", "0.0.0.0", port),
                    env,
                    ManagementFactory.getPlatformMBeanServer()
                );
                cs.start();

                log.info("Started JMXMP SASL Listener (Digest) on port " + port);
            }

            else if (Lifecycle.STOP_EVENT == event.getType()) {
                log.info("Stopp JMXMP SASL Listener (Digest)");
                cs.stop();
                log.info("Stopped JMXMP SASL Listener (Digest)");
            }

        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }
}
