package usn.net.ssl.util;

import java.net.Socket;
import java.security.Security;
import java.util.Properties;

import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.net.ssl.SSLHandshakeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link StarttlsHandler} implementation for SMTP protocol.
 */
public class StarttlsHandlerSMTP
        implements StarttlsHandler {

    private static final Logger LOG = LoggerFactory.getLogger(Starttls.class);

    @Override
    public boolean run(String host, int port, Socket tunnel) throws Exception {
        // see http://javamail.kenai.com/nonav/javadocs/com/sun/mail/smtp/package-summary.html
        
        LOG.info("... trying SMTP with STARTTLS extension ...");
        Properties mailProps = new Properties();
        mailProps.put("mail.transport.protocol", "smtp");
        mailProps.put("mail.smtp.socketFactory.class",
                "javax.net.ssl.SSLSocketFactory");
        mailProps.put("mail.smtp.socketFactory.fallback", "false");
        mailProps.put("mail.smtp.starttls.enable", "true");
        mailProps.put("mail.smtp.timeout", TimeoutSettings.getConnectionTimeout() + "");
        mailProps.put("mail.smtp.connectiontimeout", TimeoutSettings.getConnectionTimeout() + "");
        mailProps.put("mail.smtp.timeout", TimeoutSettings.getConnectionTimeout() + "");
        mailProps.put("mail.pop3.timeout", TimeoutSettings.getConnectionTimeout() + "");
        mailProps.put("mail.pop3.connectiontimeout", TimeoutSettings.getConnectionTimeout() + "");
        mailProps.put("mail.imap.timeout", TimeoutSettings.getConnectionTimeout() + "");
        mailProps.put("mail.imap.connectiontimeout", TimeoutSettings.getConnectionTimeout() + "");
        mailProps.put("mail.imap.connectionpooltimeout", TimeoutSettings.getConnectionTimeout() + "");

        Security.setProperty("ssl.SocketFactory.provider",
                SavingSSLSocketFactory.class.getName());

        Session mailSession = Session.getDefaultInstance(mailProps);
        Transport tr = null;
        try {
            tr = mailSession.getTransport();
        } catch (NoSuchProviderException e) {
            LOG.warn(e.getMessage());
            LOG.info("... trying SMTP stopped...");
            return false;
        }
        try {
            tr.connect(host, port, null, null);
        } catch (MessagingException e) {
            if (e.getNextException() instanceof SSLHandshakeException) {
                // likely got an unknown certificate, just report it and
                // return success
                LOG.info("ERROR on SSL handshake: "
                        + e.toString());
                LOG.info("... trying SMTP stopped...");
                return true;
            } else {
                LOG.info(e.getMessage());
                LOG.info("... trying SMTP stopped...");
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
        LOG.info("... trying SMTP stopped...");
        return false;
    } // run
} // class StarttlsHandlerSMTP
