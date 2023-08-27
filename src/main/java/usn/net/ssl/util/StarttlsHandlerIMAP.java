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
 * TODO make the timeouts adjustable
 * 
 * A {@link StarttlsHandler} implementation for IMAP protocol.
 */
public class StarttlsHandlerIMAP
        implements StarttlsHandler, Runnable {

    private static final Logger LOG = LoggerFactory.getLogger(Starttls.class);

    @Override
    public boolean run(String host, int port, Socket tunnel) throws Exception // see http://javamail.kenai.com/nonav/javadocs/com/sun/mail/imap/package-summary.html
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
            LOG.warn(ex.getMessage(), ex);
        }
        try {
            t.stop();
        } catch (Throwable ex) {
            LOG.warn(ex.getMessage(), ex);
        }

        return returnValue;

    } // run
    boolean returnValue = false;
    String host = "";
    int port = 0;

    @Override
    public void run() {
        LOG.info("... trying IMAP with STARTTLS extension ...");
        Properties mailProps = new Properties();
        mailProps.put("mail.store.protocol", "imap");
        mailProps.put("mail.imap.socketFactory.class",
                "javax.net.ssl.SSLSocketFactory");
        mailProps.put("mail.imap.connectionpooltimeout", TimeoutSettings.getConnectionTimeout()+"");
        mailProps.put("mail.imap.connectiontimeout", TimeoutSettings.getConnectionTimeout()+"");
        mailProps.put("mail.imap.timeout", TimeoutSettings.getConnectionTimeout()+"");
        mailProps.put("mail.imap.socketFactory.fallback", "false");
        mailProps.put("mail.imap.starttls.enable", "true");
        mailProps.put("mail.imaps.timeout", TimeoutSettings.getConnectionTimeout()+"");
        Security.setProperty("ssl.SocketFactory.provider",
                SavingSSLSocketFactory.class.getName());

        Session mailSession = Session.getDefaultInstance(mailProps);
        Store store = null;
        try {
            store = mailSession.getStore("imap");
        } catch (NoSuchProviderException e) {
            LOG.warn(e.getMessage());
            returnValue = false;
            return;
        }
        try {
            store.connect(host, port, "", "");
        } catch (AuthenticationFailedException e) {
            // likely got an unknown certificate, just report it and return
            // success
            LOG.error("ERROR on IMAP authentication: "
                    + e.toString());
            returnValue = true;
        } catch (MessagingException e) {
            LOG.warn(e.getMessage());
            returnValue = false;
        } finally {
            if (store.isConnected()) {
                try {
                    store.close();
                } catch (MessagingException e) {
                    // nothing to do here...
                }
            }

        }
        LOG.info("... trying IMAP stopped...");
    }
} // class StarttlsHandlerIMAP
