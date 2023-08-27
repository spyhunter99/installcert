package usn.net.ssl.util;

import java.net.Socket;
import java.security.Security;
import java.util.Properties;

import javax.mail.AuthenticationFailedException;
import javax.mail.MessagingException;
import javax.mail.NoSuchProviderException;
import javax.mail.Session;
import javax.mail.Store;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link StarttlsHandler} implementation for POP3 protocol.
 */
public class StarttlsHandlerPOP3
        implements StarttlsHandler, Runnable {

    private static final Logger LOG = LoggerFactory.getLogger(Starttls.class);

    @Override
    public boolean run(String host, int port, Socket tunnel) throws Exception // see http://javamail.kenai.com/nonav/javadocs/com/sun/mail/pop3/package-summary.html
    // TODO verify this method against some real POP3/STARTTLS server
    {
        this.host = host;
        this.port = port;

        final int timeout = TimeoutSettings.getOverallTimeout();
        Thread t = new Thread(this);
        t.start();

        Thread.sleep(timeout);
        t.interrupt();

        try {
            t.suspend();
        } catch (Throwable ex) {
            ex.printStackTrace();
        }
        try {
            t.stop();
        } catch (Throwable ex) {
            ex.printStackTrace();
        }

        return returnValue;
    } // run

    boolean returnValue = false;
    String host = "";
    int port = 0;

    @Override
    public void run() {
        LOG.info("... trying POP3 with STARTTLS extension ...");
        Properties mailProps = new Properties();
        mailProps.put("mail.store.protocol", "pop3");
        mailProps.put("mail.pop3.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        mailProps.put("mail.pop3.socketFactory.fallback", "false");
        mailProps.put("mail.pop3.starttls.enable", "true");

        mailProps.put("mail.smtp.timeout", TimeoutSettings.getConnectionTimeout()+"");
        mailProps.put("mail.smtp.connectiontimeout", TimeoutSettings.getConnectionTimeout()+"");
        mailProps.put("mail.pop3.timeout", TimeoutSettings.getConnectionTimeout()+"");
        mailProps.put("mail.pop3.connectiontimeout", TimeoutSettings.getConnectionTimeout()+"");
        mailProps.put("mail.imap.timeout", TimeoutSettings.getConnectionTimeout()+"");
        mailProps.put("mail.imap.connectiontimeout", TimeoutSettings.getConnectionTimeout()+"");
        mailProps.put("mail.imap.connectionpooltimeout",TimeoutSettings.getConnectionTimeout()+"");

        Security.setProperty("ssl.SocketFactory.provider",
                SavingSSLSocketFactory.class.getName());
        Session mailSession = Session.getDefaultInstance(mailProps);

        Store store = null;
        try {
            store = mailSession.getStore("pop3");
        } catch (NoSuchProviderException e) {
           LOG.warn(e.getMessage(), e);
            returnValue = false;
            return;
        }
        try {
            store.connect(host, port, "", "");
        } catch (AuthenticationFailedException e) {
            // likely got an unknown certificate, just report it and return
            // success
            LOG.error("ERROR on POP3 authentication: "
                    + e.toString());
            returnValue = false;
        } catch (MessagingException e) {
            LOG.error(e.getMessage());
            returnValue = false;
        } finally {
            if (store != null && store.isConnected()) {
                try {
                    store.close();
                } catch (MessagingException e) {
                    // nothing to do here...
                    LOG.error(e.getMessage());
                }
            }

        }

        LOG.info("... trying POP3 stopped...");
    }
} // class StarttlsHandlerPOP3
