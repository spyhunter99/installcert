package usn.net.ssl.util;

import java.security.Security;
import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.net.ssl.SSLHandshakeException;

/**
 * A {@link StarttlsHandler} implementation for SMTP protocol.
 */
public class StarttlsHandlerSMTP
        implements StarttlsHandler {

    @Override
    public boolean run(String host, int port) throws Exception // see http://javamail.kenai.com/nonav/javadocs/com/sun/mail/smtp/package-summary.html
    {
        System.out.println("... trying SMTP with STARTTLS extension ...");
        Properties mailProps = new Properties();
        mailProps.put("mail.transport.protocol", "smtp");
        mailProps.put("mail.smtp.socketFactory.class",
                "javax.net.ssl.SSLSocketFactory");
        mailProps.put("mail.smtp.socketFactory.fallback", "false");
        mailProps.put("mail.smtp.starttls.enable", "true");

        Security.setProperty("ssl.SocketFactory.provider",
                SavingSSLSocketFactory.class.getName());

        Session mailSession = Session.getDefaultInstance(mailProps);
        Transport tr = null;
        try {
            tr = mailSession.getTransport();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            return false;
        }
        try {
            tr.connect(host, port, null, null);
        } catch (MessagingException e) {
            if (e.getNextException() instanceof SSLHandshakeException) {
                // likely got an unknown certificate, just report it and
                // return success
                System.out.println("ERROR on SSL handshake: "
                        + e.toString());
                return true;
            } else {
                e.printStackTrace();
                return false;
            }
        } finally {
            if (tr.isConnected()) {
                try {
                    tr.close();
                } catch (MessagingException e) {
                    // nothing to do here...
                }
            }
        }
        return false;
    } // run
} // class StarttlsHandlerSMTP
