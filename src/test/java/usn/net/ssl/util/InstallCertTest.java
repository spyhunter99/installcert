/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package usn.net.ssl.util;

import java.io.ByteArrayInputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Set;
import org.junit.Assert;
import org.junit.Test;

/**
 *
 * @author AO
 */
public class InstallCertTest {

    /**
     * Test of certToString method, of class InstallCert.
     */
    @Test
    public void testCertToString() throws Exception {
        System.out.println("certToString");
        InstallCert x = new InstallCert();
        x.setExcludeAllTrustStates(true);
        Set<X509Certificate> certs = x.getCerts("www.google.com", 443);
        Assert.assertNotNull(certs);
        Assert.assertFalse(certs.isEmpty());

        X509Certificate cert = certs.iterator().next();

        String result = KeyStoreUtilities.certToString(cert);
        Assert.assertNotNull(certs);
        //ok now read it again

        ByteArrayInputStream bais = new ByteArrayInputStream(result.getBytes());
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
        X509Certificate cert2 = (X509Certificate) certFactory.generateCertificate(bais);
        Assert.assertNotNull(cert2);
        Assert.assertEquals(cert2, cert);
        bais.close();
    }

}
