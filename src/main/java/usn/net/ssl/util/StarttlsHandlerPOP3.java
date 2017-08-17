package usn.net.ssl.util;

import java.net.Socket;
import java.security.Security;
import java.util.Properties;

import javax.mail.AuthenticationFailedException;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Store;

/**
 * A {@link StarttlsHandler} implementation for POP3 protocol.
 */
public class StarttlsHandlerPOP3
        implements StarttlsHandler {

    @Override
    public boolean run(String host, int port,Socket tunnel) throws Exception // see http://javamail.kenai.com/nonav/javadocs/com/sun/mail/pop3/package-summary.html
    // TODO verify this method against some real POP3/STARTTLS server
    {
        System.out.println("... trying POP3 with STARTTLS extension ...");
        Properties mailProps = new Properties();
        mailProps.put("mail.store.protocol", "pop3");
        mailProps.put("mail.pop3.socketFactory.class",
                "javax.net.ssl.SSLSocketFactory");
        mailProps.put("mail.pop3.socketFactory.fallback", "false");
        mailProps.put("mail.pop3.starttls.enable", "true");

        Security.setProperty("ssl.SocketFactory.provider",
                SavingSSLSocketFactory.class.getName());

        Session mailSession = Session.getDefaultInstance(mailProps);
        Store store = null;
        try {
            store = mailSession.getStore("pop3");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }
        try {
            store.connect(host, port, "", "");
        } catch (AuthenticationFailedException e) {
            // likely got an unknown certificate, just report it and return
            // success
            System.out.println("ERROR on POP3 authentication: "
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
} // class StarttlsHandlerPOP3
