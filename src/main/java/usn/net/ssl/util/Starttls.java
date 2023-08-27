package usn.net.ssl.util;

import com.sun.mail.iap.Protocol;
import java.io.IOException;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A STARTTLS protocol extension wrapper class that makes an effort to decide on
 * the application protocol to try and runs an appropriate protocol handler.
 */
public class Starttls {

    private static final Logger LOG = LoggerFactory.getLogger(Starttls.class);
    // TODO implement NNTP/STARTTLS (119) some day...
    // TODO implement XMPP/STARTTLS (5222) some day...
    private static final Map<Integer, String> registry = new HashMap<>();

    static {
        registry.put(25, "usn.net.ssl.util.StarttlsHandlerSMTP");
        registry.put(110, "usn.net.ssl.util.StarttlsHandlerPOP3");
        registry.put(143, "usn.net.ssl.util.StarttlsHandlerIMAP");
        registry.put(389, "usn.net.ssl.util.StarttlsHandlerLDAP");
        registry.put(636, "usn.net.ssl.util.StarttlsHandlerLDAPS");
        registry.put(3268, "usn.net.ssl.util.StarttlsHandlerLDAPGC");
        registry.put(3269, "usn.net.ssl.util.StarttlsHandlerLDAPGCS");
        registry.put(5432, "usn.net.ssl.util.StarttlsHandlerPOSTGRES");
    }

    /**
     * registers a new protocol handler
     *
     * @param port port
     * @param impl fullly qualified java class name
     */
    public static void register(int port, String impl) {
        registry.put(port, impl);
    }

    /**
     * removes a specific port implementation. Useful if you don't have or want
     * a specific built in handler
     *
     * @param port
     * @param impl
     */
    public static void unregister(int port, String impl) {
        registry.remove(port);
    }

    /**
     * Guess a protocol with given port number
     *
     * @param port the port number to try
     * @return a {@link Protocol} enumeration constant, or <code>null</code> if
     * no appropriate protocol found
     */
    public static String getByPort(int port) {
        if (registry.containsKey(port)) {
            return registry.get(port);
        }
        return null;
    } // getByPort

    /**
     * Make an effort to guess the right application protocol for STARTTLS
     * extension, either by standard port or by interrogating the user; then
     * obtain the appropriate protocol handler and run it.
     *
     * @param host the host to connect to
     * @param port the port to connect to
     * @param proxyTunnel
     * @return <code>true</code> if getting a certificate via STARTTLS handler
     * is believed to be successful, <code>false</code> otherwise
     * @throws IOException
     */
    public static boolean consider(String host, int port, Socket proxyTunnel)
            throws IOException, Exception {
        String protocolForPort = getByPort(port);
        if (protocolForPort != null) {
            return obtainProtocolHandlerAndRun(protocolForPort, host, port, proxyTunnel);
        } else {
            //let's just try everything
            for (String s : registry.values()) {
                if (obtainProtocolHandlerAndRun(s, host, port, proxyTunnel)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Load a given application specific protocol STARTTLS handler and run it.
     *
     * @param handlerClassname the protocol handler name suffix, named after
     * protocol itself
     * @param host the host to connect to
     * @param port the port to connect to
     * @return <code>true</code> if getting a certificate via STARTTLS handler
     * is believed to be successful, <code>false</code> otherwise
     */
    private static boolean obtainProtocolHandlerAndRun(String handlerClassname, String host, int port, Socket proxyTunnel) throws Exception {
        Class<StarttlsHandler> handlerClass = null;
        try {
            // avoid static linking to JavaMail library and other
            // protocol-specific libraries
            @SuppressWarnings("unchecked")
            Class<StarttlsHandler> handlerUncheckedClass
                    = (Class<StarttlsHandler>) Class.forName(handlerClassname);
            handlerClass = handlerUncheckedClass;
        } catch (ClassNotFoundException e) {
            // not really observed, but we should expect may happen...
            LOG.warn("Could not find a registered handler " + handlerClassname + ". Exception: " + e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getMessage(), e);
            }
            return false;
        } catch (NoClassDefFoundError e) {
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getMessage(), e);
            }
            LOG.warn("Could not find a java class or dependency library needed for " + handlerClassname + ". Exception: " + e.getMessage());
            return false;
        }
        StarttlsHandler handler = null;
        try {
            handler = handlerClass.newInstance();
        } catch (InstantiationException e) {
            // should not happen...
            LOG.warn(e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getMessage(), e);
            }
            return false;
        } catch (IllegalAccessException e) {
            // should not happen...
            LOG.warn(e.getMessage());
            if (LOG.isDebugEnabled()) {
                LOG.debug(e.getMessage(), e);
            }
            return false;
        }
        return handler.run(host, port, proxyTunnel);
    } // obtainProtocolHandlerAndRun

} // class Starttls
