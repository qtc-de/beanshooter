/* Credits: https://github.com/felixoldenburg/jmxmp-lifecycle-listener */
package javax.management.remote.extension;

import java.util.HashMap;
import java.lang.management.ManagementFactory;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

public class JMXMPSslLifecycleListener implements LifecycleListener
{
    protected int port = 5556;
    protected JMXConnectorServer cs;
    private static final Log log = LogFactory.getLog(JMXMPSslLifecycleListener.class);

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
                log.info("Starting JMXMP SSL Listener");

                HashMap env = new HashMap();
                SSLContext ctx = SSLContext.getDefault();
                SSLSocketFactory ssf = ctx.getSocketFactory(); 
                env.put("jmx.remote.profiles", "TLS"); 
                env.put("jmx.remote.tls.socket.factory", ssf); 

                cs = JMXConnectorServerFactory.newJMXConnectorServer(
                    new JMXServiceURL("jmxmp", "0.0.0.0", port),
                    env,
                    ManagementFactory.getPlatformMBeanServer()
                );
                cs.start();

                log.info("Started JMXMP SSL Listener on port " + port);
            }

            else if (Lifecycle.STOP_EVENT == event.getType()) {
                log.info("Stopp JMXMP SSL Listener");
                cs.stop();
                log.info("Stopped JMXMP SSL Listener");
            }

        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }
}
