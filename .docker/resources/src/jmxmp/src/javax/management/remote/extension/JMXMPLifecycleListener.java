/* Credits: https://github.com/felixoldenburg/jmxmp-lifecycle-listener */
package javax.management.remote.extension;

import java.lang.management.ManagementFactory;

import javax.management.remote.JMXConnectorServer;
import javax.management.remote.JMXConnectorServerFactory;
import javax.management.remote.JMXServiceURL;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

public class JMXMPLifecycleListener implements LifecycleListener
{
    protected int port = 5555;
    protected JMXConnectorServer cs;
    private static final Log log = LogFactory.getLog(JMXMPLifecycleListener.class);

    public int getPort() {
        return port;
    }

    public void setPort(final int port) {
        this.port = port;
    }

    @Override
    public void lifecycleEvent(final LifecycleEvent event)
    {
        try {

            if (Lifecycle.START_EVENT == event.getType()) {
                log.info("Starting JMXMP Listener");

                cs = JMXConnectorServerFactory.newJMXConnectorServer(
                    new JMXServiceURL("jmxmp", "0.0.0.0", port),
                    null,
                    ManagementFactory.getPlatformMBeanServer()
                );
                cs.start();

                log.info("Started JMXMP Listener on port " + port);
            }

            else if (Lifecycle.STOP_EVENT == event.getType()) {
                log.info("Stopp JMXMP Listener");
                cs.stop();
                log.info("Stopped JMXMP Listener");
            }

        } catch (final Exception e) {
            throw new RuntimeException(e);
        }
    }
}
