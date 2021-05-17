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
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLHandshakeException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.DatatypeConverter;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

import sun.security.provider.certpath.SunCertPathBuilderException;
import sun.security.validator.ValidatorException;
import static usn.net.ssl.util.InstallCert.certToString;
import static usn.net.ssl.util.InstallCert.findTrustStores;

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

    private static final Logger LOG = Logger.getLogger(InstallCert.class.getName());
    private static final char[] DEFAULT = "changeit".toCharArray();
    final static String PROGRAM_TERMINATED = "Program terminated.";

    final static String EXTRA_CERTS_FILE_NAME = "extracerts";

    //this is also the only variable that prevents this class from being thread safe.
    // this one is needed here to allow being shared with embedded classes
    private static SSLContext context;

    private static void saveCerts(Set<X509Certificate> certsToSave, String host) throws Exception {
        for (X509Certificate cert : certsToSave) {
            String alias = host + " - " + getCommonName(cert);
            alias = alias.replaceAll("[^a-zA-Z0-9\\.\\-]", "_");
            File file = null;
            file = new File(alias + ".crt");
            int i = 0;
            while (file.exists()) {
                file = new File(alias + "-" + i + ".crt");
            }
            FileWriter fw = new FileWriter(file);
            fw.write(certToString(cert));
            fw.close();
            System.out.println("Cert saved to: " + file.getAbsolutePath());
        }
    }

    public static String certToString(X509Certificate cert) throws CertificateEncodingException {
        StringWriter sw = new StringWriter();

        sw.write("-----BEGIN CERTIFICATE-----\n");
        sw.write(DatatypeConverter.printBase64Binary(cert.getEncoded()).replaceAll("(.{64})", "$1\n"));
        sw.write("\n-----END CERTIFICATE-----\n");

        return sw.toString();
    }

    private static Set<? extends KeyStoreWrapper> scanWindowsCommon(String tmp) {

        //TODO this only covers windows at the moment
        Set<KeyStoreWrapper> wrappers = new HashSet<KeyStoreWrapper>();
        File pf = new File(tmp);
        File java = new File(tmp, "Java");
        if (java.exists()) {

            File[] javaInstalls = pf.listFiles(new FileFilter() {
                @Override
                public boolean accept(File pathname) {
                    return (pathname.isDirectory() && pathname.getName().equalsIgnoreCase("java"));
                }
            });

            if (javaInstalls != null) {
                for (File javaRoot : javaInstalls) {

                    File[] javaVersion = javaRoot.listFiles(new FileFilter() {
                        @Override
                        public boolean accept(File pathname) {
                            return (pathname.isDirectory());
                        }
                    });
                    for (File file : javaVersion) {

                        wrappers.addAll(scanJavaInstall(file));

                    }
                }
            }
        }

        return wrappers;
    }

    private static Collection<? extends KeyStoreWrapper> scanJavaInstall(File file) {
        Set<KeyStoreWrapper> wrappers = new HashSet<KeyStoreWrapper>();
        if (file == null || !file.exists()) {
            return wrappers;
        }
        File cacerts = new File(file, "lib/security/cacerts");
        if (cacerts.exists()) {
            KeyStoreWrapper wrapper = new KeyStoreWrapper();
            wrapper.keyStoreLocation = cacerts;
            wrapper.keyStorePassword = DEFAULT;
            try {
                wrapper.store = getKeyStore(wrapper.keyStoreLocation, wrapper.keyStorePassword);
                wrappers.add(wrapper);
            } catch (Exception ex) {
                LOG.log(Level.WARNING, ex.getMessage(), ex);
            }
        }
        cacerts = new File(file, "jre/lib/security/cacerts");
        if (cacerts.exists()) {
            KeyStoreWrapper wrapper = new KeyStoreWrapper();
            wrapper.keyStoreLocation = cacerts;
            wrapper.keyStorePassword = DEFAULT;
            try {
                wrapper.store = getKeyStore(wrapper.keyStoreLocation, wrapper.keyStorePassword);
                wrappers.add(wrapper);
            } catch (Exception ex) {
                LOG.log(Level.WARNING, ex.getMessage(), ex);
            }
        }
        return wrappers;
    }

    public static SSLContext getContext() {
        return context;
    }

    public static Set<KeyStoreWrapper> findTrustStores() {
        Set<KeyStoreWrapper> ret = new HashSet<KeyStoreWrapper>();
        //FIXME support non-windows setups
        String tmp = System.getenv("ProgramFiles");
        if (tmp != null) {
            ret.addAll(scanWindowsCommon(tmp));
        }
        tmp = System.getenv("ProgramFiles(x86)");
        if (tmp != null) {
            ret.addAll(scanWindowsCommon(tmp));
        }
        tmp = System.getProperty("java.home");
        if (tmp != null) {
            ret.addAll(scanWindowsCommon(tmp));
        }
        tmp = System.getenv("JAVA_HOME");
        if (tmp != null) {
            ret.addAll(scanJavaInstall(new File(tmp)));
        }
        return ret;
    }

    public static KeyStore getKeyStore(File file, char[] password) throws Exception {
        KeyStore ksKnown = KeyStore.getInstance(KeyStore.getDefaultType());

        System.out.println("... loading system truststore from '"
                + file.getCanonicalPath() + "' ...");
        InputStream in = new FileInputStream(file);
        ksKnown.load(in, password);
        in.close();
        return ksKnown;
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
        opts.addOption("password", true, "if specified, your value will be used for the trust store password. if not specified the default jre password will be used");
        opts.addOption("passwordExtra", true, "if specified, password for the extra trust store");
        opts.addOption("noimport", false, "if specified, no changes will be made to trust stores");
        opts.addOption("file", false, "if specified, untrusted certificates will be stored to individial .crt files");
        opts.addOption("danger", false, "don't prompt for confirmation, all certificates returned will be auto trusted");
        opts.addOption("skipDisco", false, "skip automatic JRE trust store detection");
        /*
        * useful for when the current JRE trust's something, but the target JRE that needs to be
        * updated does not
         */
        opts.addOption("exclude", false, "Exclues trustworthiness from all trust stores");

        CommandLineParser parser = new DefaultParser();
        CommandLine inputs = parser.parse(opts, args);

        if (!inputs.hasOption("host")) {
            new HelpFormatter().printHelp("java -jar install-cert-<VERSION>-jar-with-dependencies.jar", opts);
            return;
        }

        InstallCert ref = new InstallCert();

        // handle command line arguments
        String host = null;
        int port = 0;

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
            ref.trustStoresToModify.addAll(findTrustStores());
        }

        if (inputs.hasOption("truststore")) {
            ref.addTrustStore(new File(inputs.getOptionValue("truststore")), password);
        }

        if (inputs.hasOption("truststoreExtra")) {
            storeLocation2 = new File(inputs.getOptionValue("truststoreExtra"));
            ref.addTrustStore(storeLocation2, pwd2);
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
                System.out.println();
                System.out.println(ref.prettyPrintCertificate(cert, "\n"));

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
                System.out.println("Skipping JKS import due to -noimport flag");
            } else {
                ref.applyChanges(certsToSave, host);
            }

        } else {
            System.out.println();
            System.out.println("No new certificates found to be added.");
        }
    } // main

    protected static String joinStringArray(String[] array, String delimiter) {
        StringBuilder sb = new StringBuilder();
        for (String s : array) {
            if (sb.length() > 0) {
                sb.append(delimiter);
            }
            sb.append(s);
        }
        return sb.toString();
    } // joinStringArray

    protected static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            sb.append(String.format("%02x ", b & 0xff));
        }
        return sb.toString();
    } // toHexString

    protected static String ask(String prompt)
            throws IOException {
        System.out.print(prompt);
        BufferedReader stdinReader
                = new BufferedReader(new InputStreamReader(System.in));
        String line = stdinReader.readLine().trim();
        return line;
    } // ask

    public static String getCommonName(X509Certificate cert)
            throws InvalidNameException {
        // use LDAP API to parse the certifiate Subject :)
        // see http://stackoverflow.com/a/7634755/972463
        LdapName ldapDN
                = new LdapName(cert.getSubjectX500Principal().getName());
        String cn = "";
        for (Rdn rdn : ldapDN.getRdns()) {
            if (rdn.getType().equals("CN")) {
                cn = rdn.getValue().toString();
            }
        }
        return cn;
    }  // getCommonName
    private boolean excludeAllTrustStates = false;

    private MessageDigest sha1 = null;
    private MessageDigest md5 = null;
    private Set<KeyStoreWrapper> trustStoresToModify = new HashSet<KeyStoreWrapper>();

    public InstallCert() {
        try {
            sha1 = MessageDigest.getInstance("SHA1");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(InstallCert.class.getName()).log(Level.SEVERE, null, ex);
        }
        try {
            md5 = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(InstallCert.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public List<File> getTrustStores() {
        List<File> files = new ArrayList<File>();
        for (KeyStoreWrapper wrapper : trustStoresToModify) {
            files.add(wrapper.keyStoreLocation);
        }
        return files;
    }

    public boolean isExcludeAllTrustStates() {
        return excludeAllTrustStates;
    }

    public void setExcludeAllTrustStates(boolean excludeAllTrustStates) {
        this.excludeAllTrustStates = excludeAllTrustStates;
    }

    public void addTrustStore(File file, char[] password) throws Exception {
        KeyStoreWrapper wrapper = new KeyStoreWrapper();
        wrapper.keyStoreLocation = file;
        wrapper.keyStorePassword = password;
        wrapper.store = getKeyStore(file, password);
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
            tmf.init((KeyStore)null);
        } catch (Exception ex) {
            LOG.log(Level.WARNING, "failed to null trust store ", ex);
        }
        // initialize it with known certificate data
        for (KeyStoreWrapper wrapper : trustStoresToModify) {
            try {
                tmf.init(wrapper.store);
            } catch (Exception ex) {
                LOG.log(Level.WARNING, "failed to apply trust store " + wrapper.keyStoreLocation.getAbsolutePath(), ex);
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
            System.out.println("Opening socket to proxy " + tunnelHost + ":" + tunnelPort + "...");
            tunnel = new Socket(tunnelHost, tunnelPort);
            doTunnelHandshake(tunnel, host, port);
        }

        System.out.println("Opening connection to " + host + ":" + port + "...");

        System.out.println("... opening connection to " + host + ":" + port
                + " ...");
        SSLSocket sslSocket = null;
        try {

            if (tunnel != null) {
                System.out.println("Using proxy configuration. proxy: " + tunnelHost + ":" + tunnelPort);
                sslSocket = (SSLSocket) factory.createSocket(tunnel, host, port, true);
            } else {
                sslSocket = (SSLSocket) factory.createSocket(host, port);
            }

            sslSocket.setSoTimeout(10000);
            System.out.println("... starting SSL handshake ...");

            sslSocket.startHandshake();
            System.out.println("No errors, certificate is already trusted.");
        } // SMTP/STARTTLS and IMAP/STARTTLS servers seem tending to yield an
        //   SSLException with
        //   "Unrecognized SSL message, plaintext connection?" message.
        // LDAP/STARTTLS servers seem tending to yield an
        //   SSLHandshakeException with nested EOFException or a
        //   SocketException with "Connection reset" message.
        // Thus three distinct cases for considering a STARTTLS extension below
        catch (SSLHandshakeException e) {
            if (e.getCause().getClass().equals(ValidatorException.class)
                    && e.getCause().getCause().getClass().equals(SunCertPathBuilderException.class)) {
                // this is the standard case: looks like we just got a
                // previously unknown certificate, so report it and go
                // ahead...
                System.out.println(e.toString());
            } else if (e.getCause().getClass().getName().equals("java.io.EOFException")) // "Remote host closed connection during handshake"
            {
                // close the unsuccessful SSL socket
                if (sslSocket != null) {
                    sslSocket.close();
                }
                // consider trying STARTTLS extension over ordinary socket
                if (!Starttls.consider(host, port, tunnel)) {
                    // Starttls.consider () is expected to have reported
                    // everything except the final good-bye...
                    System.out.println(e.getMessage());
                }
            } else {
                e.printStackTrace();
            }
        } catch (SSLException e) {
            if (e.getMessage().equals("Unrecognized SSL message, plaintext connection?")) {
                System.out.println("ERROR on SSL handshake: "
                        + e.toString());
                if (sslSocket != null) {
                    sslSocket.close();
                }
                // consider trying STARTTLS extension over ordinary socket
                if (!Starttls.consider(host, port, tunnel)) {
                    // Starttls.consider () is expected to have reported
                    // everything except the final good-bye...
                    System.out.println(e.getMessage());
                }
            } else {
                System.out.println(e.getMessage());
            }
        } catch (SocketException e) {
            if (e.getMessage().equals("Connection reset")) {
                System.out.println("ERROR on SSL handshake: "
                        + e.toString());
                if (sslSocket != null) {
                    sslSocket.close();
                }
                // consider trying STARTTLS extension over ordinary socket
                if (!Starttls.consider(host, port, tunnel)) {
                    // Starttls.consider () is expected to have reported
                    // everything except the final good-bye...
                    System.out.println(e.getMessage());
                }
            } else {
                System.out.println(e.getMessage());
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
            System.out.println();
            System.out.println("Server sent " + chain.length
                    + " certificate(s):");

            for (int i = 0; i < chain.length; i++) {
                X509Certificate cert = chain[i];

                boolean trusted = false;
                for (KeyStoreWrapper wrapper : trustStoresToModify) {
                    if (wrapper.store.getCertificateAlias(cert) != null) {
                        System.out.println("Certificate already known to the"
                                + " truststore: " + wrapper.keyStoreLocation.getAbsolutePath());
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
            wrapper.store = null;
            wrapper.keyStoreLocation = null;
            for (int i = 0; i < wrapper.keyStorePassword.length; i++) {
                wrapper.keyStorePassword[i] = (char) 0;
            }
            wrapper.keyStorePassword = null;
        }
        trustStoresToModify.clear();
    }

    /**
     * see https://github.com/escline/InstallCert/issues/9
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

    public String prettyPrintCertificate(X509Certificate cert, String newLine) throws InvalidNameException, CertificateEncodingException {
        StringBuilder sb = new StringBuilder();

        sb.append("Subject ").append(cert.getSubjectDN()).append(newLine);
        sb.append("   Issuer  ").append(cert.getIssuerDN()).append(newLine);
        sb.append("   CN      ").append(getCommonName(cert)).append(newLine);
        sb.append("   From    ").append(cert.getNotBefore().toString()).append(newLine);
        sb.append("   Util    ").append(cert.getNotAfter().toString()).append(newLine);
        sb.append("   Serial  ").append(cert.getSerialNumber().toString()).append(newLine);
        if (sha1 != null) {
            sha1.update(cert.getEncoded());
            sb.append("   SHA1    ").append(toHexString(sha1.digest())).append(newLine);
        }
        if (md5 != null) {
            md5.update(cert.getEncoded());

            sb.append("   MD5     ").append(toHexString(md5.digest())).append(newLine);
        }
        return sb.toString();
    }

    public void applyChanges(Set<X509Certificate> certsToSave, String host) throws Exception {

        if (trustStoresToModify.isEmpty()) {
            throw new Exception("must initialize a trust store");
        }

        for (KeyStoreWrapper wrapper : trustStoresToModify) {
            System.out.println("Applying changes to " + wrapper.keyStoreLocation.getAbsolutePath());

            // assign aliases using host name and certificate common name
            for (X509Certificate cert : certsToSave) {
                String alias = host + " - " + getCommonName(cert);
                wrapper.store.setCertificateEntry(alias, cert);
            }

            OutputStream out = new FileOutputStream(wrapper.keyStoreLocation);
            wrapper.store.store(out, wrapper.keyStorePassword);
            out.close();

        }
    }

    public static class KeyStoreWrapper {

        private KeyStore store;
        private File keyStoreLocation;
        private char[] keyStorePassword;

        public KeyStore getStore() {
            return store;
        }

        public void setStore(KeyStore store) {
            this.store = store;
        }

        public File getKeyStoreLocation() {
            return keyStoreLocation;
        }

        public void setKeyStoreLocation(File keyStoreLocation) {
            this.keyStoreLocation = keyStoreLocation;
        }

        public char[] getKeyStorePassword() {
            return keyStorePassword;
        }

        public void setKeyStorePassword(char[] keyStorePassword) {
            this.keyStorePassword = keyStorePassword;
        }

        @Override
        public boolean equals(Object other) {
            if (other instanceof KeyStoreWrapper) {
                return keyStoreLocation.equals(((KeyStoreWrapper) other).keyStoreLocation);
            }
            return false;
        }

        @Override
        public int hashCode() {
            int hash = 7;
            hash = 41 * hash + (this.keyStoreLocation != null ? this.keyStoreLocation.hashCode() : 0);
            return hash;
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
                    Enumeration<String> ksAliases = wrapper.store.aliases();
                    while (ksAliases.hasMoreElements()) {
                        String alias = ksAliases.nextElement();
                        try {
                            this.allAccumulatedCerts.add((X509Certificate) wrapper.store.getCertificate(alias));
                        } catch (Exception ex) {
                            ex.printStackTrace();
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

