package usn.net.ssl.util;

import java.io.IOException;

/**
 * A STARTTLS protocol extension wrapper class that makes an effort to decide on
 * the application protocol to try and runs an appropriate protocol handler.
 */
public class Starttls {

    // TODO implement NNTP/STARTTLS (119) some day...
    // TODO implement XMPP/STARTTLS (5222) some day...
    /**
     * Enumeration of known application-level TCP-based protocols that support
     * STARTTLS extension, with their standard port numbers.
     */
    public enum Protocol {
        SMTP(25),
        POP3(110),
        IMAP(143),
        LDAP(389),
        LDAPS(636),
        LDAPGC(3268),
        LDAPGCS(3269),
        POSTGRES(5432);

        /**
         * The standard port for a protocol
         */
        int port;

        /**
         * The constructor for a given standard port
         *
         * @param port the standard port for a protocol
         */
        Protocol(int port) {
            this.port = port;
        } // Protocols

        /**
         * Guess a protocol with given port number
         *
         * @param port the port number to try
         * @return a {@link Protocol} enumeration constant, or <code>null</code>
         * if no appropriate protocol found
         */
        static public Starttls.Protocol getByPort(int port) {
            for (Starttls.Protocol p : Protocol.values()) {
                if (p.port == port) {
                    return p;
                }
            }
            return null;
        } // getByPort

    } // enum Protocol

    /**
     * Make an effort to guess the right application protocol for STARTTLS
     * extension, either by standard port or by interrogating the user; then
     * obtain the appropriate protocol handler and run it.
     *
     * @param host the host to connect to
     * @param port the port to connect to
     * @return <code>true</code> if getting a certificate via STARTTLS handler
     * is believed to be successful, <code>false</code> otherwise
     * @throws IOException
     */
    public static boolean consider(String host, int port)
            throws IOException, Exception {
        Starttls.Protocol protocolForPort = Protocol.getByPort(port);
        if (protocolForPort != null) {
            return obtainProtocolHandlerAndRun(protocolForPort.name(), host, port);
        } else {
            //let's just try everything
            Protocol[] vals = Protocol.values();
            for (int i = 0; i < vals.length; i++) {

                if (obtainProtocolHandlerAndRun(vals[i].name(), host, port)) {
                    return true;
                }
            }
            return false;
        }
    } // consider

    /**
     * Load a given application specific protocol STARTTLS handler and run it.
     *
     * @param handlerSuffix the protocol handler name suffix, named after
     * protocol itself
     * @param host the host to connect to
     * @param port the port to connect to
     * @return <code>true</code> if getting a certificate via STARTTLS handler
     * is believed to be successful, <code>false</code> otherwise
     */
    private static boolean obtainProtocolHandlerAndRun(String handlerSuffix, String host, int port) throws Exception {
        Class<StarttlsHandler> handlerClass = null;
        try {
            // avoid static linking to JavaMail library and other
            // protocol-specific libraries
            @SuppressWarnings("unchecked")
            Class<StarttlsHandler> handlerUncheckedClass
                    = (Class<StarttlsHandler>) Class.forName(StarttlsHandler.class.getName() + handlerSuffix);
            handlerClass = handlerUncheckedClass;
        } catch (ClassNotFoundException e) {
            // not really observed, but we should expect may happen...
            throw e;
        } catch (NoClassDefFoundError e) {
            if (e.getCause().getClass()
                    .equals(ClassNotFoundException.class)
                    && e.getCause().getMessage()
                            .equals("javax.mail.NoSuchProviderException")) {
                System.out.println("ERROR loading protocol-specific STARTTLS handler: "
                        + e.toString());
                System.out.println("Looks like you need to make JavaMail library "
                        + "available on your classpath, something like this:\n"
                        + "  java -cp " + System.getProperty("java.class.path")
                        + System.getProperty("path.separator") + "..."
                        + System.getProperty("file.separator") + "javax.mail.jar "
                        + "usn.net.ssl.util.InstallCert ");
                throw e;
            } else {
                // provide more info for analysis...
                throw e;
            }
        }
        StarttlsHandler handler = null;
        try {
            handler = handlerClass.newInstance();
        } catch (InstantiationException e) {
            // should not happen...
            e.printStackTrace();
            return false;
        } catch (IllegalAccessException e) {
            // should not happen...
            e.printStackTrace();
            return false;
        }
        return handler.run(host, port);
    } // obtainProtocolHandlerAndRun

} // class Starttls
