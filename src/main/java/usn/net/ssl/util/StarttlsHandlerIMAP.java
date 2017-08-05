package usn.net.ssl.util;

import java.security.Security;
import java.util.Properties;

import javax.mail.AuthenticationFailedException;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Store;

/**
 * A {@link StarttlsHandler} implementation for IMAP protocol.
 */
public class StarttlsHandlerIMAP
        implements StarttlsHandler {

    @Override
    public boolean run(String host, int port) // see http://javamail.kenai.com/nonav/javadocs/com/sun/mail/imap/package-summary.html
    {
        System.out.println("... trying IMAP with STARTTLS extension ...");
        Properties mailProps = new Properties();
        mailProps.put("mail.store.protocol", "imap");
        mailProps.put("mail.imap.socketFactory.class",
                "javax.net.ssl.SSLSocketFactory");
        mailProps.put("mail.imap.socketFactory.fallback", "false");
        mailProps.put("mail.imap.starttls.enable", "true");

        Security.setProperty("ssl.SocketFactory.provider",
                SavingSSLSocketFactory.class.getName());

        Session mailSession = Session.getDefaultInstance(mailProps);
        Store store = null;
        try {
            store = mailSession.getStore("imap");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }
        try {
            store.connect(host, port, "", "");
        } catch (AuthenticationFailedException e) {
            // likely got an unknown certificate, just report it and return
            // success
            System.out.println("ERROR on IMAP authentication: "
                    + e.toString());
            return true;
        } catch (MessagingException e) {
            e.printStackTrace();
            return false;
        } finally {
            if (store.isConnected()) {
                try {
                    store.close();
                } catch (MessagingException e) {
                    // nothing to do here...
                }
            }
        }
        return false;
    } // run
} // class StarttlsHandlerIMAP
