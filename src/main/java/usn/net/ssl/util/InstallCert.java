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
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.SocketException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;

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
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Options;

import sun.security.provider.certpath.SunCertPathBuilderException;
import sun.security.validator.ValidatorException;

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

    final static String PROGRAM_TERMINATED = "Program terminated.";

    final static String EXTRA_CERTS_FILE_NAME = "extracerts";

    //this is also the only variable that prevents this class from being thread safe.
    // this one is needed here to allow being shared with embedded classes
    private static SSLContext context;

    private KeyStore store;
    private File keyStoreLocation;
    private char[] keyStorePassword;
    private KeyStore store2;
    private File keyStoreLocation2;
    private char[] keyStorePassword2;

    public static SSLContext getContext() {
        return context;
    }

    private void setTrustStore(File file, char[] password) throws Exception {
        keyStoreLocation = file;
        keyStorePassword = password;
        store = getKeyStore(file, password);
    }

    private void setExtraTrustStore(File file, char[] password) throws Exception {
        keyStoreLocation2 = file;
        keyStorePassword2 = password;
        store2 = getKeyStore(file, password);
    }

    public static File getJreDefaultKeyStore() {
        char SEP = File.separatorChar;
        File systemSecurityDir = new File(System.getProperty("java.home")
                + SEP + "lib" + SEP + "security");
        File file = new File(systemSecurityDir, "jssecacerts");
        if (!file.exists()) {
            file = new File(systemSecurityDir, "cacerts");
        }
        return file;
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

    public void setTrustStore(final KeyStore store) {
        this.store = store;
    }

    public void setExtraTrustStore(final KeyStore store) {
        this.store2 = store;
    }

    /**
     * returns a potentially empty list of certificates that are not trusted
     *
     * @param host
     * @param port
     * @return
     */
    public synchronized Set<X509Certificate> getCerts(String host, int port) throws Exception {

        // obtain an instance of a TLS SSLContext
        context = SSLContext.getInstance("TLS");

        // obtain a TrustManagerFactory instance
        TrustManagerFactory tmf
                = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());

        // initialize it with known certificate data
        tmf.init(store);

        // obtain default TrustManager instance
        X509TrustManager defaultTrustManager
                = (X509TrustManager) tmf.getTrustManagers()[0];

        SavingTrustManager tm
                = new SavingTrustManager(defaultTrustManager, store);
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        System.out.println("... opening connection to " + host + ":" + port
                + " ...");
        SSLSocket sslSocket = null;
        try {
            sslSocket = (SSLSocket) factory.createSocket(host, port);
        
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
                sslSocket.close();
                // consider trying STARTTLS extension over ordinary socket
                if (!Starttls.consider(host, port)) {
                    // Starttls.consider () is expected to have reported
                    // everything except the final good-bye...
                    e.printStackTrace();
                }
            } else {
                e.printStackTrace();
            }
        } catch (SSLException e) {
            if (e.getMessage().equals("Unrecognized SSL message, plaintext connection?")) {
                System.out.println("ERROR on SSL handshake: "
                        + e.toString());
                sslSocket.close();
                // consider trying STARTTLS extension over ordinary socket
                if (!Starttls.consider(host, port)) {
                    // Starttls.consider () is expected to have reported
                    // everything except the final good-bye...
                    e.printStackTrace();
                }
            } else {
                e.printStackTrace();
            }
        } catch (SocketException e) {
            if (e.getMessage().equals("Connection reset")) {
                System.out.println("ERROR on SSL handshake: "
                        + e.toString());
                sslSocket.close();
                // consider trying STARTTLS extension over ordinary socket
                if (!Starttls.consider(host, port)) {
                    // Starttls.consider () is expected to have reported
                    // everything except the final good-bye...
                    e.printStackTrace();
                }
            } else {
                e.printStackTrace();
            }
        } finally {
            if (!sslSocket.isClosed()) {
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

                if (store.getCertificateAlias(cert) != null) {
                    System.out.println("Certificate already known to the"
                            + " system truststore.");
                } else if (store2 != null && store2.getCertificateAlias(cert) != null) {
                    System.out.println("Certificate already known to the"
                            + " extra truststore.");
                } else {
                    certsToSave.add(cert);
                }
            }
        }
        return certsToSave;
    }
    
    /**
     * clears all settings and nullifies are cached passwords.
     * This should be called when this object is no longer needed
     */
    public void close(){
        if (this.keyStorePassword!=null) {
            clearPassword(keyStorePassword);
        }
        if (this.keyStorePassword2!=null) {
            clearPassword(keyStorePassword2);
        }
        this.keyStorePassword=null;
        this.keyStorePassword2=null;
        this.store=null;
        this.store2=null;
        this.keyStoreLocation=null;
        this.keyStoreLocation2=null;
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
        File storeLocation = getJreDefaultKeyStore();

        char[] pwd2 = null;
        File storeLocation2 = null;

        // handle standard arguments
        String[] c = inputs.getOptionValue("host").split(":");
        host = c[0];
        port = (c.length < 2) ? 443 : Integer.parseInt(c[1]);
        if (inputs.hasOption("password")) {
            password = inputs.getOptionValue("password").toCharArray();
        } else {
            password = "changeit".toCharArray();
        }
        if (inputs.hasOption("passwordExtra")) {
            pwd2 = inputs.getOptionValue("passwordExtra").toCharArray();
        } else {
            pwd2 = "changeit".toCharArray();
        }

        if (inputs.hasOption("truststore")) {
            ref.setTrustStore(new File(inputs.getOptionValue("truststore")), password);
        } else {
            storeLocation = getJreDefaultKeyStore();

            ref.setTrustStore(storeLocation, password);

        }

        if (inputs.hasOption("truststoreExtra")) {
            storeLocation2 = new File(inputs.getOptionValue("truststoreExtra"));
            ref.setExtraTrustStore(storeLocation2, pwd2);
        }

        Set<X509Certificate> untrustedCerts = ref.getCerts(host, port);
        Set<X509Certificate> certsToSave = new HashSet<X509Certificate>();
        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");

        // save the new certificates approved by the user
        if (!untrustedCerts.isEmpty()) {
            // assign aliases using host name and certificate common name
            for (X509Certificate cert : untrustedCerts) {
                System.out.println();
                System.out.println("Subject "
                        + cert.getSubjectDN());
                System.out.println("   Issuer  " + cert.getIssuerDN());
                System.out.println("   CN      " + getCommonName(cert));
                sha1.update(cert.getEncoded());
                System.out.println("   sha1    "
                        + toHexString(sha1.digest()));
                md5.update(cert.getEncoded());
                System.out.println("   md5     "
                        + toHexString(md5.digest()));
                System.out.print("Do you want to trust this certifcate (y/n)? > ");
                String answer = System.console().readLine();
                if ("y".equalsIgnoreCase(answer)) {
                    certsToSave.add(cert);
                }

            }
        } 

        // save the new certificates approved by the user
        if (!certsToSave.isEmpty()) {

            ref.applyChanges(certsToSave, host);

        } else {
            System.out.println();
            System.out.println("No new certificates found to be added.");
        }
    } // main
    
    
    private static void clearPassword(char[] pwd) {
        if (pwd==null) return;
        for (int i=0; i < pwd.length; i++) {
            pwd[i] = '\0';
        }
    }

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

    private void applyChanges(Set<X509Certificate> certsToSave, String host) throws Exception {
        // assign aliases using host name and certificate common name
        for (X509Certificate cert : certsToSave) {
            String alias = host + " - " + getCommonName(cert);
            store.setCertificateEntry(alias, cert);
            if (store2 != null) {
                store2.setCertificateEntry(alias, cert);
            }
            System.out.println();
            System.out.println(cert);
            System.out.println();
            System.out.println("Certificate will be added using alias '" + alias + "'.");
        }

        // save them to the extra truststore for certificates known just
        // locally
        System.out.println();
        System.out.println("... adding certificate(s) to the truststore ...");
        OutputStream out = new FileOutputStream(keyStoreLocation);
        store.store(out, keyStorePassword);
        out.close();
        if (store2 != null) {
            System.out.println("... adding certificate(s) to the extra truststore ...");
            out = new FileOutputStream(keyStoreLocation2);
            store2.store(out, keyStorePassword2);
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
                KeyStore ksExtra)
                throws KeyStoreException {
            if (parentTm == null) {
                throw new IllegalArgumentException("Parent trust manager cannot be null.");
            } else {
                this.parentTm = parentTm;
            }
            if (ksExtra != null) {
                Enumeration<String> ksAliases = ksExtra.aliases();
                while (ksAliases.hasMoreElements()) {
                    String alias = ksAliases.nextElement();
                    this.allAccumulatedCerts.add((X509Certificate) ksExtra.getCertificate(alias));
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

