/*
 * Copyright 2006 Sun Microsystems, Inc.  All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   - Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *   - Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *
 *   - Neither the name of Sun Microsystems nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
 * IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package usn.net.ssl.util;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * <p>
 * A program to obtain SSL certificate(s) from a host and save them to a
 * keystore and optionally install them in local JSSE storage; the program
 * collects SSL/TLS certificates from plain SSL/TLS hosts, and also from hosts
 * that operate with STARTTLS extension for LDAP, SMTP, POP3 and IMAP.</p>
 * <p>
 * <b>Original article:</b> <a
 *     href="http://blogs.sun.com/andreas/entry/no_more_unable_to_find"
 * >http://blogs.sun.com/andreas/entry/no_more_unable_to_find</a><br>
 * <b>Original source:</b> <a
 *     href="http://blogs.sun.com/andreas/resource/InstallCert.java"
 * >http://blogs.sun.com/andreas/resource/InstallCert.java</a><br>
 * <b>Author:</b> Andreas Sterbenz, 2006</p>
 * <p>
 * <b>Currently available at:</b> <a
 *     href="https://java.net/projects/javamail/pages/InstallCert"
 * >https://java.net/projects/javamail/pages/InstallCert</a><br>
 * <b>Current Google Code branch as web page:</b> <a
 *     href="http://code.google.com/p/java-use-examples/source/browse/trunk/src/com/aw/ad/util/InstallCert.java"
 * >http://code.google.com/p/java-use-examples/source/browse/trunk/src/com/aw/ad/util/InstallCert.java</a
 * ><br>
 * <b>Current Google Code branch as Java code:</b> <a
 *     href="http://java-use-examples.googlecode.com/svn/trunk/src/com/aw/ad/util/InstallCert.java"
 * >http://java-use-examples.googlecode.com/svn/trunk/src/com/aw/ad/util/InstallCert.java</a
 * ><br>
 * <b>Source path in Google Code repository:</b> <code>svn/ trunk/ src/ com/
 *     aw/ ad/ util/ InstallCert.java</code></p>
 * <p>
 * <b>Approach to STARTTLS with JavaMail</b>: Eugen Kuleshov and Dmitry I.
 * Platonoff, JavaWorld.com, August 31, 2001<br>
 * <a href="http://www.javaworld.com/javatips/jw-javatip115.html">Java Tip 115:
 * Secure JavaMail with JSSE</a></p>
 * <p>
 * <b>Merged together by:</b> Sergey Ushakov (usn), 2012&ndash;2013</p>
 * <p>
 * <b>Use without STARTTLS extension for SMTP, POP3 and IMAP protocols:</b><br>
 * <code>java -jar installcert-usn-....jar {@literal <host>[:<port>]
 *     [<truststore_password>]}</code><br>
 * Default port is 443.<br>
 * Default truststore password is "changeit" as per JSSE convention.<br>
 * The program uses a keystore file named "extracerts" in the current directory
 * to store the new certificates, and also attempts to add them to the standard
 * system keystore <code>jssecacerts</code>, see <a
 *     href="http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html#X509TrustManager"
 * >http://docs.oracle.com/javase/7/docs/technotes/guides/security/jsse/JSSERefGuide.html#X509TrustManager</a
 * >.</p>
 * <p>
 * <b>Example:</b><br>
 * <code>java -jar installcert-usn-20140115.jar
 *     ecc.fedora.redhat.com</code></p>
 * <p>
 * <b>Use with STARTTLS extension for SMTP, POP3 and IMAP protocols:</b><br>
 * <i>on Windows:</i><br>
 * <code>java -cp installcert-usn-....jar;.../javax.mail.jar
 *     usn.net.ssl.util.InstallCert {@literal <host>[:<port>]
 *     [<password>]}</code><br>
 * <i>on *ix:</i><br>
 * <code>java -cp installcert-usn-....jar:.../javax.mail.jar
 *     usn.net.ssl.util.InstallCert {@literal <host>[:<port>]
 *     [<password>]}</code><br>
 * Be sure to provide the real path to your local copy of
 * <code>javax.mail.jar</code> :)</p>
 * <p>
 * See Oracle <a
 *     href="http://www.oracle.com/technetwork/java/sslnotes-150073.txt"
 * >Notes for use of SSL with JavaMail</a>.</p>
 */
public class InstallCert {

    private static final Logger LOG = LoggerFactory.getLogger(InstallCert.class.getName());
    public static final char[] DEFAULT = "changeit".toCharArray();

    //this is also the only variable that prevents this class from being thread safe.
    // this one is needed here to allow being shared with embedded classes
    private static SSLContext context;
    public static MessageDigest sha1 = null;
    public static MessageDigest md5 = null;

    static {
        try {
            sha1 = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException ex) {
            LOG.info("SHA1 not available " + ex.getMessage());
        }
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            LOG.info("MD5 not available " + ex.getMessage());
        }
    }

    private static void saveCerts(Set<X509Certificate> certsToSave, String host) throws Exception {
        for (X509Certificate cert : certsToSave) {
            String alias = host + " - " + KeyStoreUtilities.getCommonName(cert);
            alias = alias.replaceAll("[^a-zA-Z0-9\\.\\-]", "_");
            File file = null;
            file = new File(alias + ".crt");
            int i = 0;
            while (file.exists()) {
                file = new File(alias + "-" + i + ".crt");
            }
            FileWriter fw = new FileWriter(file);
            fw.write(KeyStoreUtilities.certToString(cert));
            fw.close();
            LOG.info("Cert saved to: " + file.getAbsolutePath());
        }
    }

    public static SSLContext getContext() {
        return context;
    }

    /**
     * Run the program from command line.
     *
     * @param args command line arguments as: <code>{@literal <host>[:<port>]
     *             [<truststore_password>]}</code>
     * @throws Exception
     */
    public static void main(final String[] args)
            throws Exception {

        Options opts = new Options();
        opts.addOption("host", true, "The host:port of the server to pull a ssl cert chain from. If not specified, 443 will be used.");
        opts.addOption("truststore", true, "if specified, this trust store will be used, otherwise JAVA_HOME/cacerts will be used");
        opts.addOption("truststoreExtra", true, "if specified, this trust store will also be used");
        opts.addOption("truststoreType", true, "if specified, overrides the default trust store type of " + KeyStore.getDefaultType());
        opts.addOption("password", true, "if specified, your value will be used for the trust store password. if not specified the default jre password will be used");
        opts.addOption("passwordExtra", true, "if specified, password for the extra trust store");
        opts.addOption("noimport", false, "if specified, no changes will be made to trust stores");
        opts.addOption("file", false, "if specified, untrusted certificates will be stored to individial .crt files");
        opts.addOption("danger", false, "don't prompt for confirmation, all certificates returned will be auto trusted");
        opts.addOption("skipDisco", false, "skip automatic JRE trust store detection");
        opts.addOption("connectTimeout", true, "Time in millsecinds for connection attempts. Default is 10 seconds");
        opts.addOption("overallTimeout", true, "Time in millsecinds for a connection attempt for specific use cases. Default is 15 seconds");
        /*
        * useful for when the current JRE trust's something, but the target JRE that needs to be
        * updated does not
         */
        opts.addOption("exclude", false, "Exclues trustworthiness from all trust stores");

        CommandLineParser parser = new DefaultParser();
        CommandLine inputs = parser.parse(opts, args);

        if (inputs.hasOption("connectTimeout")) {
            TimeoutSettings.setConnectionTimeout(Integer.parseInt(inputs.getOptionValue("connectTimeout")));
        }
        if (inputs.hasOption("overallTimeout")) {
            TimeoutSettings.setOverallTimeout(Integer.parseInt(inputs.getOptionValue("overallTimeout")));
        }

        if (!inputs.hasOption("host")) {
            new HelpFormatter().printHelp("java -jar install-cert-<VERSION>-jar-with-dependencies.jar", opts);
            return;
        }

        InstallCert ref = new InstallCert();

        // handle command line arguments
        String host = null;
        int port = 0;
        String trustStoreType = KeyStore.getDefaultType();
        if (inputs.hasOption("truststoreType")) {
            trustStoreType = inputs.getOptionValue("truststoreType");
        }
        char[] password = null;

        char[] pwd2 = null;
        File storeLocation2 = null;

        // handle standard arguments
        String[] c = inputs.getOptionValue("host").split(":");
        host = c[0];
        port = (c.length < 2) ? 443 : Integer.parseInt(c[1]);
        if (inputs.hasOption("password")) {
            password = inputs.getOptionValue("password").toCharArray();
        } else {
            password = DEFAULT;
        }
        if (inputs.hasOption("passwordExtra")) {
            pwd2 = inputs.getOptionValue("passwordExtra").toCharArray();
        } else {
            pwd2 = DEFAULT;
        }

        //option for no trust store discovery
        if (!inputs.hasOption("skipDisco")) {
            ref.trustStoresToModify.addAll(KeyStoreUtilities.findTrustStores());
        }

        if (inputs.hasOption("truststore")) {
            ref.addTrustStore(new File(inputs.getOptionValue("truststore")), password, trustStoreType);
        }

        if (inputs.hasOption("truststoreExtra")) {
            storeLocation2 = new File(inputs.getOptionValue("truststoreExtra"));
            ref.addTrustStore(storeLocation2, pwd2, trustStoreType);
        }

        if (inputs.hasOption("exclude")) {
            ref.setExcludeAllTrustStates(true);
        }

        Set<X509Certificate> untrustedCerts = ref.getCerts(host, port);
        Set<X509Certificate> certsToSave = new HashSet<X509Certificate>();

        // save the new certificates approved by the user
        if (!untrustedCerts.isEmpty()) {
            // assign aliases using host name and certificate common name
            for (X509Certificate cert : untrustedCerts) {
                LOG.info(KeyStoreUtilities.prettyPrintCertificate(cert, "\n"));

                if (inputs.hasOption("danger")) {
                    certsToSave.add(cert);
                } else {
                    System.out.print("Do you want to trust this certifcate (y/n)? > ");
                    String answer = System.console().readLine();
                    if ("y".equalsIgnoreCase(answer)) {
                        certsToSave.add(cert);
                    }
                }

            }
        }

        // save the new certificates approved by the user
        if (!certsToSave.isEmpty()) {

            if (inputs.hasOption("file")) {
                saveCerts(certsToSave, host);
            }
            if (inputs.hasOption("noimport")) {
                LOG.info("Skipping JKS import due to -noimport flag");
            } else {
                ref.applyChanges(certsToSave, host);
            }

        } else {
            LOG.info("No new certificates found to be added.");
        }
    } // main

    protected static String ask(String prompt)
            throws IOException {
        System.out.print(prompt);
        BufferedReader stdinReader
                = new BufferedReader(new InputStreamReader(System.in));
        String line = stdinReader.readLine().trim();
        return line;
    } // ask

    private boolean excludeAllTrustStates = false;

    private Set<KeyStoreWrapper> trustStoresToModify = new HashSet<KeyStoreWrapper>();

    public InstallCert() {

    }

    public List<File> getTrustStores() {
        List<File> files = new ArrayList<File>();
        for (KeyStoreWrapper wrapper : trustStoresToModify) {
            files.add(wrapper.getKeyStoreLocation());
        }
        return files;
    }

    /**
     * if true, and provided trust store, including the built in JRE/JDK trust
     * stores will be ignored with processing. meaning you'll get a set of all
     * certificates in the trust chain for the remote server, whether or not
     * it's trusted
     *
     * @return true/false
     */
    public boolean isExcludeAllTrustStates() {
        return excludeAllTrustStates;
    }

    public void setExcludeAllTrustStates(boolean excludeAllTrustStates) {
        this.excludeAllTrustStates = excludeAllTrustStates;
    }

    /**
     * adds a trust store to use for both connecting to a server and for
     * applying changes
     *
     * @param file
     * @param password
     * @throws Exception
     */
    public void addTrustStore(File file, char[] password) throws Exception {
        addTrustStore(file, password, KeyStore.getDefaultType());
    }

    /**
     * adds a trust store to use for both connecting to a server and for
     * applying changes
     *
     * @param file
     * @param password
     * @throws Exception
     */
    public void addTrustStore(File file, char[] password, String keystoreType) throws Exception {
        KeyStoreWrapper wrapper = new KeyStoreWrapper();
        wrapper.setKeyStoreLocation(file);
        wrapper.setKeyStorePassword(password);
        wrapper.setStore(KeyStoreUtilities.getKeyStore(file, password, keystoreType));
        trustStoresToModify.add(wrapper);
    }

    public void addAll(Set<KeyStoreWrapper> set) {
        this.trustStoresToModify.addAll(set);
    }

    /**
     * returns a potentially empty list of certificates that are not trusted
     *
     * @param host
     * @param port
     * @return
     */
    public synchronized Set<X509Certificate> getCerts(String host, int port) throws Exception {

        //if (trustStoresToModify.isEmpty()) {
        //    throw new Exception("must initialize the trust store(s) first");
        //}
        // obtain an instance of a TLS SSLContext
        context = SSLContext.getInstance("TLS");

        // obtain a TrustManagerFactory instance
        TrustManagerFactory tmf
                = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        try {
            tmf.init((KeyStore) null);
        } catch (Exception ex) {
            LOG.warn("failed to null trust store ", ex);
        }
        // initialize it with known certificate data
        for (KeyStoreWrapper wrapper : trustStoresToModify) {
            try {
                tmf.init(wrapper.getStore());
            } catch (Exception ex) {
                LOG.warn("failed to apply trust store " + wrapper.getKeyStoreLocation().getAbsolutePath(), ex);
            }
        }

        // obtain default TrustManager instance
        X509TrustManager defaultTrustManager
                = (X509TrustManager) tmf.getTrustManagers()[0];
        if (excludeAllTrustStates) {
            defaultTrustManager = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                    throw new CertificateException(string);
                }

                @Override
                public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
                    throw new CertificateException(string);
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
        }
        SavingTrustManager tm
                = new SavingTrustManager(defaultTrustManager, trustStoresToModify);
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        /*
         * Set up a socket to do tunneling through the proxy.
         * Start it off as a regular socket, then layer SSL
         * over the top of it.
         */
        String tunnelHost = System.getProperty("https.proxyHost");
        String tunnelPortStr = System.getProperty("https.proxyPort");
        int tunnelPort = 0;
        if ((tunnelPortStr != null) && (!tunnelPortStr.trim().isEmpty())) {
            // Integer tunnelPortInteger = Integer.getInteger(tunnelPortStr);
            // tunnelPort = (tunnelPortInteger != null) ? tunnelPortInteger.intValue() : 0;
            tunnelPort = Integer.parseInt(tunnelPortStr);
        }

        Socket tunnel = null;
        if ((tunnelHost != null) && (!tunnelHost.trim().isEmpty())) {
            LOG.info("Opening socket to proxy " + tunnelHost + ":" + tunnelPort + "...");
            tunnel = new Socket(tunnelHost, tunnelPort);
            doTunnelHandshake(tunnel, host, port);
        }

        LOG.info("Opening connection to " + host + ":" + port + "...");

        LOG.info("... opening connection to " + host + ":" + port
                + " ...");
        SSLSocket sslSocket = null;
        try {

            if (tunnel != null) {
                LOG.info("Using proxy configuration. proxy: " + tunnelHost + ":" + tunnelPort);
                sslSocket = (SSLSocket) factory.createSocket(tunnel, host, port, true);
            } else {
                sslSocket = (SSLSocket) factory.createSocket(host, port);
            }

            sslSocket.setSoTimeout(TimeoutSettings.getConnectionTimeout());
            LOG.info("... starting SSL handshake ...");

            sslSocket.startHandshake();
            LOG.info("No errors, certificate is already trusted.");
        } // SMTP/STARTTLS and IMAP/STARTTLS servers seem tending to yield an
        //   SSLException with
        //   "Unrecognized SSL message, plaintext connection?" message.
        // LDAP/STARTTLS servers seem tending to yield an
        //   SSLHandshakeException with nested EOFException or a
        //   SocketException with "Connection reset" message.
        // Thus three distinct cases for considering a STARTTLS extension below
        catch (SSLHandshakeException e) {
            if (e.getCause() != null
                    && e.getCause().getClass().getSimpleName().equals("ValidatorException")
                    && e.getCause().getCause() != null
                    && e.getCause().getCause().getClass().getSimpleName().equals("SunCertPathBuilderException")) {
                // this is the standard case: looks like we just got a
                // previously unknown certificate, so report it and go
                // ahead...
                LOG.info(e.getMessage());
            } else if (e.getCause() != null
                    && e.getCause().getClass().getName().equals("java.io.EOFException")) // "Remote host closed connection during handshake"
            {
                // close the unsuccessful SSL socket
                if (sslSocket != null) {
                    sslSocket.close();
                }
                // consider trying STARTTLS extension over ordinary socket
                if (!Starttls.consider(host, port, tunnel)) {
                    // Starttls.consider () is expected to have reported
                    // everything except the final good-bye...
                    LOG.info(e.getMessage());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(e.getMessage(), e);
                    }
                }
            } else {
                LOG.info(e.toString());
                if (LOG.isDebugEnabled()) {
                    LOG.debug(e.getMessage(), e);
                }
            }
        } catch (SSLException e) {
            if (e.getMessage().equals("Unrecognized SSL message, plaintext connection?")) {
                LOG.info("ERROR on SSL handshake: "
                        + e.toString());
                if (LOG.isDebugEnabled()) {
                    LOG.debug(e.getMessage(), e);
                }
                if (sslSocket != null) {
                    sslSocket.close();
                }
                // consider trying STARTTLS extension over ordinary socket
                if (!Starttls.consider(host, port, tunnel)) {
                    // Starttls.consider () is expected to have reported
                    // everything except the final good-bye...
                    LOG.info(e.getMessage());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(e.getMessage(), e);
                    }
                }
            } else {
                LOG.info(e.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug(e.getMessage(), e);
                }
            }
        } catch (SocketException e) {
            if (e.getMessage().equals("Connection reset")) {
                LOG.info("ERROR on SSL handshake: "
                        + e.toString());
                if (LOG.isDebugEnabled()) {
                    LOG.debug(e.getMessage(), e);
                }
                if (sslSocket != null) {
                    sslSocket.close();
                }
                // consider trying STARTTLS extension over ordinary socket
                if (!Starttls.consider(host, port, tunnel)) {
                    // Starttls.consider () is expected to have reported
                    // everything except the final good-bye...
                    LOG.info(e.getMessage());
                    if (LOG.isDebugEnabled()) {
                        LOG.debug(e.getMessage(), e);
                    }
                }
            } else {
                LOG.info(e.getMessage());
                if (LOG.isDebugEnabled()) {
                    LOG.debug(e.getMessage(), e);
                }
            }
        } finally {

            if (sslSocket != null && !sslSocket.isClosed()) {
                sslSocket.close();
            }
        }

        // get the full set of new accumulated certificates as an array
        X509Certificate[] chain
                = tm.newCerts.toArray(new X509Certificate[0]);

        // an empty set for certificates to be selected for saving 
        Set<X509Certificate> certsToSave = new HashSet<X509Certificate>();

        // display the list of obtained certificates, inspect them and
        // interrogate the user whether to save them
        if (chain.length > 0) {
            LOG.info("Server sent " + chain.length
                    + " certificate(s):");

            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = chain[i];

                boolean trusted = false;
                for (KeyStoreWrapper wrapper : trustStoresToModify) {
                    if (wrapper.getStore().getCertificateAlias(cert) != null) {
                        LOG.info("Certificate already known to the"
                                + " truststore: " + wrapper.getKeyStoreLocation().getAbsolutePath());
                        trusted = true;
                        break;
                    }
                }
                if (!trusted) {
                    certsToSave.add(cert);
                }

            }
        }
        return certsToSave;
    }

    /**
     * clears all settings and nullifies are cached passwords. This should be
     * called when this object is no longer needed
     */
    public void close() {

        for (KeyStoreWrapper wrapper : trustStoresToModify) {
            wrapper.clear();

        }
        trustStoresToModify.clear();
    }

    /**
     * Proxy support see https://github.com/escline/InstallCert/issues/9
     *
     * @author vpablos@github
     * @param tunnel
     * @param host
     * @param port
     * @throws IOException
     */
    private void doTunnelHandshake(Socket tunnel, String host, int port)
            throws IOException {
        OutputStream out = tunnel.getOutputStream();
        String msg = "CONNECT " + host + ":" + port + " HTTP/1.0\n"
                + "User-Agent: "
                + sun.net.www.protocol.http.HttpURLConnection.userAgent
                + "\r\n\r\n";
        byte b[];
        try {
            /*
         * We really do want ASCII7 -- the http protocol doesn't change
         * with locale.
             */
            b = msg.getBytes("ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            /*
         * If ASCII7 isn't there, something serious is wrong, but
         * Paranoia Is Good (tm)
             */
            b = msg.getBytes();
        }
        out.write(b);
        out.flush();

        /*
      * We need to store the reply so we can create a detailed
      * error message to the user.
         */
        byte reply[] = new byte[200];
        int replyLen = 0;
        int newlinesSeen = 0;
        boolean headerDone = false;
        /* Done on first newline */

        InputStream in = tunnel.getInputStream();
        boolean error = false;

        while (newlinesSeen < 2) {
            int i = in.read();
            if (i < 0) {
                throw new IOException("Unexpected EOF from proxy");
            }
            if (i == '\n') {
                headerDone = true;
                ++newlinesSeen;
            } else if (i != '\r') {
                newlinesSeen = 0;
                if (!headerDone && replyLen < reply.length) {
                    reply[replyLen++] = (byte) i;
                }
            }
        }

        /*
      * Converting the byte array to a string is slightly wasteful
      * in the case where the connection was successful, but it's
      * insignificant compared to the network overhead.
         */
        String replyStr;
        try {
            replyStr = new String(reply, 0, replyLen, "ASCII7");
        } catch (UnsupportedEncodingException ignored) {
            replyStr = new String(reply, 0, replyLen);
        }

        /* We check for Connection Established because our proxy returns 
       * HTTP/1.1 instead of 1.0 */
        //if (!replyStr.startsWith("HTTP/1.0 200")) {
        if (replyStr.toLowerCase().indexOf(
                "200 connection established") == -1) {
            throw new IOException("Unable to tunnel through "
                    + host + ":" + port
                    + ".  Proxy returns \"" + replyStr + "\"");
        }

        /* tunneling Handshake was successful! */
    }

    public void applyChanges(Set<X509Certificate> certsToSave, String host) throws Exception {

        if (trustStoresToModify.isEmpty()) {
            throw new Exception("must initialize a trust store");
        }

        for (KeyStoreWrapper wrapper : trustStoresToModify) {
            LOG.info("Applying changes to " + wrapper.getKeyStoreLocation().getAbsolutePath());

            // assign aliases using host name and certificate common name
            for (X509Certificate cert : certsToSave) {
                String alias = host + " - " + KeyStoreUtilities.getCommonName(cert);
                wrapper.getStore().setCertificateEntry(alias, cert);
            }

            OutputStream out = new FileOutputStream(wrapper.getKeyStoreLocation());
            wrapper.getStore().store(out, wrapper.getKeyStorePassword());
            out.close();

        }
    }

    // -- class SavingTrustManager ---------------------------------------------
    /**
     * An {@link X509TrustManager} subclass that accumulates unknown
     * certificates in order to allow saving them afterwards.
     */
    protected static class SavingTrustManager implements X509TrustManager {

        protected X509TrustManager parentTm;
        protected Set<X509Certificate> allAccumulatedCerts
                = new HashSet<X509Certificate>();
        protected Set<X509Certificate> newCerts
                = new HashSet<X509Certificate>();

        /**
         * The constructor.
         *
         * @param parentTm an {@link X509TrustManager} instance to do the
         * standard part of certificates validation job
         * @param ksExtra a {@link KeyStore} instance that contains previously
         * accumulated certificates
         * @throws KeyStoreException
         */
        SavingTrustManager(X509TrustManager parentTm,
                Set<KeyStoreWrapper> ksExtra)
                throws KeyStoreException {
            if (parentTm == null) {
                throw new IllegalArgumentException("Parent trust manager cannot be null.");
            } else {
                this.parentTm = parentTm;
            }
            if (ksExtra != null) {
                for (KeyStoreWrapper wrapper : ksExtra) {
                    Enumeration<String> ksAliases = wrapper.getStore().aliases();
                    while (ksAliases.hasMoreElements()) {
                        String alias = ksAliases.nextElement();
                        try {
                            this.allAccumulatedCerts.add((X509Certificate) wrapper.getStore().getCertificate(alias));
                        } catch (Exception ex) {
                            LOG.info(ex.getMessage());
                            if (LOG.isDebugEnabled()) {
                                LOG.debug(ex.getMessage(), ex);
                            }

                        }
                    }
                }
            }
        } // SavingTrustManager

        // .. javax.net.ssl.X509TrustManager methods ...........................
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            throw new UnsupportedOperationException();
        } // checkClientTrusted

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            CertificateException exceptionToRethrow = null;
            // check the certificate chain against the system truststore
            try {
                parentTm.checkServerTrusted(chain, authType);
            } catch (CertificateException e) // the certificate chain was found not trusted
            {
                // check if the first certificate in the chain is not known yet
                //   to the local certificate storage
                if (!this.allAccumulatedCerts.contains(chain[0])) {
                    // save the exception to be re-thrown later if not known
                    exceptionToRethrow = e;
                    // save the full chain to both local accumulators
                    for (X509Certificate cert : chain) {
                        this.allAccumulatedCerts.add(cert);
                        this.newCerts.add(cert);
                    }
                }
            }
            // check and re-throw the exception if any 
            if (exceptionToRethrow != null) {
                throw exceptionToRethrow;
            }
        } // checkServerTrusted

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return this.parentTm.getAcceptedIssuers();
        } // getAcceptedIssuers

    } // class SavingTrustManager

} // class InstallCert

