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
 * A {@link StarttlsHandler} implementation for IMAP protocol.
 */
public class StarttlsHandlerIMAP
        implements StarttlsHandler, Runnable {

    @Override
    public boolean run(String host, int port, Socket tunnel) throws Exception // see http://javamail.kenai.com/nonav/javadocs/com/sun/mail/imap/package-summary.html
    {
        this.host = host;
        this.port = port;

        final int timeout = 5000;
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
        System.out.println("... trying IMAP with STARTTLS extension ...");
        Properties mailProps = new Properties();
        mailProps.put("mail.store.protocol", "imap");
        mailProps.put("mail.imap.socketFactory.class",
                "javax.net.ssl.SSLSocketFactory");
        mailProps.put("mail.imap.connectionpooltimeout", "3000");
        mailProps.put("mail.imap.connectiontimeout", "3000");
        mailProps.put("mail.imap.timeout", "3000");
        mailProps.put("mail.imap.socketFactory.fallback", "false");
        mailProps.put("mail.imap.starttls.enable", "true");
        mailProps.put("mail.imaps.timeout", "3000");
        Security.setProperty("ssl.SocketFactory.provider",
                SavingSSLSocketFactory.class.getName());

        Session mailSession = Session.getDefaultInstance(mailProps);
        Store store = null;
        try {
            store = mailSession.getStore("imap");
        } catch (NoSuchProviderException e) {
            System.out.println(e.getMessage());
            returnValue = false;
        }
        try {
            store.connect(host, port, "", "");
        } catch (AuthenticationFailedException e) {
            // likely got an unknown certificate, just report it and return
            // success
            System.out.println("ERROR on IMAP authentication: "
                    + e.toString());
            returnValue = true;
        } catch (MessagingException e) {
            System.out.println(e.getMessage());
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
         System.out.println("... trying IMAP with stopped...");
    }
} // class StarttlsHandlerIMAP
