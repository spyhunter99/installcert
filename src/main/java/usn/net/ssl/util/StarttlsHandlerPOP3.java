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
        implements StarttlsHandler, Runnable {

    @Override
    public boolean run(String host, int port, Socket tunnel) throws Exception // see http://javamail.kenai.com/nonav/javadocs/com/sun/mail/pop3/package-summary.html
    // TODO verify this method against some real POP3/STARTTLS server
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
        System.out.println("... trying POP3 with STARTTLS extension ...");
        Properties mailProps = new Properties();
        mailProps.put("mail.store.protocol", "pop3");
        mailProps.put("mail.pop3.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
        mailProps.put("mail.pop3.socketFactory.fallback", "false");
        mailProps.put("mail.pop3.starttls.enable", "true");
        
        
        mailProps.put("mail.smtp.timeout", "1000");
        mailProps.put("mail.smtp.connectiontimeout", "1000");
        mailProps.put("mail.pop3.timeout", "1000");
        mailProps.put("mail.pop3.connectiontimeout", "1000");
        mailProps.put("mail.imap.timeout", "1000");
        mailProps.put("mail.imap.connectiontimeout", "1000");
        mailProps.put("mail.imap.connectionpooltimeout", "1000");


        Security.setProperty("ssl.SocketFactory.provider",
                SavingSSLSocketFactory.class.getName());
        Session mailSession = Session.getDefaultInstance(mailProps);

        Store store = null;
        try {
            store = mailSession.getStore("pop3");
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
            returnValue = false;
        }
        try {
            store.connect(host, port, "", "");
        } catch (AuthenticationFailedException e) {
            // likely got an unknown certificate, just report it and return
            // success
            System.out.println("ERROR on POP3 authentication: "
                    + e.toString());
            returnValue = false;
        } catch (MessagingException e) {
            System.out.println(e);
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
        
        System.out.println("... trying POP3 with stopped...");
    }
} // class StarttlsHandlerPOP3
