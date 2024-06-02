package usn.net.ssl.util;

import java.io.File;
import java.io.FileFilter;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.apache.commons.codec.binary.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author AO
 */
public class KeyStoreUtilities {

    private static final Logger LOG = LoggerFactory.getLogger(KeyStoreUtilities.class.getName());

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

    public static String getCommonName(X509Certificate cert) throws InvalidNameException {
        // use LDAP API to parse the certifiate Subject :)
        // see http://stackoverflow.com/a/7634755/972463
        LdapName ldapDN = new LdapName(cert.getSubjectX500Principal().getName());
        String cn = "";
        for (Rdn rdn : ldapDN.getRdns()) {
            if (rdn.getType().equals("CN")) {
                cn = rdn.getValue().toString();
            }
        }
        return cn;
    } // getCommonName

    public static KeyStore getKeyStore(File file, char[] password) throws Exception {
        return getKeyStore(file, password, KeyStore.getDefaultType());
    }

    public static KeyStore getKeyStore(File file, char[] password, String trustStoreType) throws Exception {
        KeyStore ksKnown = KeyStore.getInstance(KeyStore.getDefaultType());
        LOG.info("... loading system truststore from '" + file.getCanonicalPath() + "' ...");
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            ksKnown.load(in, password);
        } finally {
            if (in != null) {
                in.close();
            }
        }

        return ksKnown;
    }

    private static Collection<? extends KeyStoreWrapper> scanJavaInstall(File file) {
        Set<KeyStoreWrapper> wrappers = new HashSet<KeyStoreWrapper>();
        if (file == null || !file.exists()) {
            return wrappers;
        }
        File cacerts = new File(file, "lib/security/cacerts");
        if (cacerts.exists()) {
            KeyStoreWrapper wrapper = new KeyStoreWrapper();
            wrapper.setKeyStoreLocation(cacerts);
            wrapper.setKeyStorePassword(InstallCert.DEFAULT);
            try {
                wrapper.setStore(getKeyStore(wrapper.getKeyStoreLocation(), wrapper.getKeyStorePassword()));
                wrappers.add(wrapper);
            } catch (Exception ex) {
                LOG.warn(ex.getMessage(), ex);
                if (LOG.isDebugEnabled()) {
                    LOG.debug(ex.getMessage(), ex);
                }
            }
        }
        cacerts = new File(file, "jre/lib/security/cacerts");
        if (cacerts.exists()) {
            KeyStoreWrapper wrapper = new KeyStoreWrapper();
            wrapper.setKeyStoreLocation(cacerts);
            wrapper.setKeyStorePassword(InstallCert.DEFAULT);
            try {
                wrapper.setStore(getKeyStore(wrapper.getKeyStoreLocation(), wrapper.getKeyStorePassword()));
                wrappers.add(wrapper);
            } catch (Exception ex) {
                LOG.warn(ex.getMessage(), ex);
                if (LOG.isDebugEnabled()) {
                    LOG.debug(ex.getMessage(), ex);
                }
            }
        }
        return wrappers;
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
                    return pathname.isDirectory() && pathname.getName().equalsIgnoreCase("java");
                }
            });
            if (javaInstalls != null) {
                for (File javaRoot : javaInstalls) {
                    File[] javaVersion = javaRoot.listFiles(new FileFilter() {
                        @Override
                        public boolean accept(File pathname) {
                            return pathname.isDirectory();
                        }
                    });
                    if (javaVersion != null) {
                        for (File file : javaVersion) {
                            wrappers.addAll(scanJavaInstall(file));
                        }
                    }
                }
            }
        }
        return wrappers;
    }

    public static String certToString(X509Certificate cert) throws CertificateEncodingException {
        StringWriter sw = new StringWriter();
        sw.write("-----BEGIN CERTIFICATE-----\n");
        String encoded = Base64.encodeBase64String(cert.getEncoded());
        sw.write(encoded.replaceAll("(.{64})", "$1\n"));
        sw.write("\n-----END CERTIFICATE-----\n");
        return sw.toString();
    }

    public static String toHexString(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int b : bytes) {
            sb.append(String.format("%02x ", b & 255));
        }
        return sb.toString();
    } // toHexString

    public static String prettyPrintCertificate(X509Certificate cert, String newLine) throws InvalidNameException, CertificateEncodingException {
        StringBuilder sb = new StringBuilder();
        sb.append("Subject ").append(cert.getSubjectDN()).append(newLine);
        sb.append("   Issuer  ").append(cert.getIssuerDN()).append(newLine);
        sb.append("   CN      ").append(getCommonName(cert)).append(newLine);
        sb.append("   From    ").append(cert.getNotBefore().toString()).append(newLine);
        sb.append("   Util    ").append(cert.getNotAfter().toString()).append(newLine);
        sb.append("   Serial  ").append(cert.getSerialNumber().toString()).append(newLine);
        if (InstallCert.sha1 != null) {
            InstallCert.sha1.update(cert.getEncoded());
            sb.append("   SHA1    ").append(toHexString(InstallCert.sha1.digest())).append(newLine);
        }
        if (InstallCert.md5 != null) {
            InstallCert.md5.update(cert.getEncoded());
            sb.append("   MD5     ").append(toHexString(InstallCert.md5.digest())).append(newLine);
        }
        return sb.toString();
    }

    public static String joinStringArray(String[] array, String delimiter) {
        StringBuilder sb = new StringBuilder();
        for (String s : array) {
            if (sb.length() > 0) {
                sb.append(delimiter);
            }
            sb.append(s);
        }
        return sb.toString();
    } // joinStringArray

}
