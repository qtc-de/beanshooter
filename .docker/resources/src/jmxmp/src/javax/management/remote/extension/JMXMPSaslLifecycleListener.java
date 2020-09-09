/* Credits: https://github.com/felixoldenburg/jmxmp-lifecycle-listener */
package javax.management.remote.extension;

import java.lang.management.ManagementFactory;
import java.security.Security;
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

public class JMXMPSaslLifecycleListener implements LifecycleListener
{
    protected int port = 5556;
    protected JMXConnectorServer cs;
    private static final Log log = LogFactory.getLog(JMXMPSaslLifecycleListener.class);

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
                log.debug("Starting JMXMP SASL Listener (PLAIN)");

                HashMap env = new HashMap();
                SSLContext ctx = SSLContext.getDefault();
                SSLSocketFactory ssf = ctx.getSocketFactory();
                Security.addProvider(new com.sun.jdmk.security.sasl.Provider());
                env.put("jmx.remote.profiles", "TLS SASL/PLAIN");
                env.put("jmx.remote.sasl.callback.handler", new AuthenticationCallBackHandler());
                env.put("jmx.remote.x.access.file", "/opt/jmxmp.access");
                env.put("jmx.remote.tls.socket.factory", ssf);

                cs = JMXConnectorServerFactory.newJMXConnectorServer(
                    new JMXServiceURL("jmxmp", "0.0.0.0", port),
                    env,
                    ManagementFactory.getPlatformMBeanServer()
                );
                cs.start();

                log.info("Started JMXMP SASL Listener (PLAIN) on port " + port);
            }

            else if (Lifecycle.STOP_EVENT == event.getType()) {
                log.debug("Stopp JMXMP SASL Listener (PLAIN)");
                cs.stop();
                log.info("Stopped JMXMP SASL Listener (PLAIN)");
            }

        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }
}
