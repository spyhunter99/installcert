package usn.net.ssl.util;

import java.net.Socket;

/**
 * An interface to be implemented by application protocol specific STARTTLS
 * handlers, to be used by {@link Starttls} class.
 */
public interface StarttlsHandler {

    /**
     * Do the application protocol specific actions to initiate a protocol
     * specific STARTTLS session, starting from a new connection.
     *
     * @param host the host to connect to
     * @param port the port to connect to
     * @return <code>true</code> if getting a certificate via STARTTLS is
     * believed to be successful, <code>false</code> otherwise
     * @throws java.lang.Exception
     */
    boolean run(String host, int port, Socket tunnel) throws Exception;
} // interface StarttlsHandler
