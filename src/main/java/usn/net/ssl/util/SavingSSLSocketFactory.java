package usn.net.ssl.util;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509TrustManager;

/**
 * An {@link SSLSocketFactory} subclass that takes care of using
 * {@link InstallCert.SavingTrustManager} as {@link X509TrustManager} subclass
 * to collect server certificates and allows creating unconnected sockets, as
 * required by JavaMail protocol handlers. This class is made public in order to
 * allow being configured as the factory to be used by JavaMail properties
 * mechanism, etc.
 */
public class SavingSSLSocketFactory
        extends SSLSocketFactory {

    SSLSocketFactory factory;

    public SavingSSLSocketFactory() throws Exception {
        try {
            this.factory = InstallCert.getContext().getSocketFactory();

        } catch (Exception e) {
            throw e;
        }
    } // SavingSSLSocketFactory

    // .. javax.net.ssl.SSLSocketFactory methods ...........................
    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose)
            throws IOException {
        return factory.createSocket(s, host, port, autoClose);
    } // createSocket

    @Override
    public String[] getDefaultCipherSuites() {
        return factory.getDefaultCipherSuites();
    } // getDefaultCipherSuites

    @Override
    public String[] getSupportedCipherSuites() {
        return factory.getSupportedCipherSuites();
    } // getSupportedCipherSuites

    // .. javax.net.SocketFactory methods ..................................
    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress,
            int localPort)
            throws IOException {
        return factory.createSocket(address, port, localAddress, localPort);
    } // createSocket

    @Override
    public Socket createSocket(InetAddress host, int port)
            throws IOException {
        return factory.createSocket(host, port);
    } // createSocket

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException {
        return factory.createSocket(host, port, localHost, localPort);
    } // createSocket

    @Override
    public Socket createSocket(String host, int port)
            throws IOException {
        return factory.createSocket(host, port);
    } // createSocket

    /**
     * Bypass the default <code>javax.net.SocketFactory</code> implementation
     * that throws <code>java.net.SocketException</code> with nested
     * <code>java.lang.UnsupportedOperationException</code> with "Unconnected
     * sockets not implemented" message.
     */
    @Override
    public Socket createSocket()
            throws IOException {
        return new Socket();
    } // createSocket

} // class SavingSSLSocketFactory
