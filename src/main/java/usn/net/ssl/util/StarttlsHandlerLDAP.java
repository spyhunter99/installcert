package usn.net.ssl.util;

import java.io.IOException;
import java.net.Socket;
import java.util.Hashtable;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLHandshakeException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A {@link StarttlsHandler} implementation for LDAP protocol.
 */
public class StarttlsHandlerLDAP
        implements StarttlsHandler {
    private static final Logger LOG = LoggerFactory.getLogger(Starttls.class);

    private SSLContext sslContext;

    public StarttlsHandlerLDAP() {
        this.sslContext = InstallCert.getContext();
    }
    
    public String getUrlPrefix(){
        return "ldap://";
    }

    @Override
    public boolean run(String host, int port, Socket tunnel) throws Exception // see http://docs.oracle.com/javase/jndi/tutorial/ldap/ext/starttls.html
    // see http://docs.oracle.com/javase/7/docs/technotes/guides/jndi/jndi-ldap.html
    {
        LOG.info("... trying LDAP with STARTTLS extension ...");

        Hashtable<String, String> env = new Hashtable<String, String>();
        env.put(Context.INITIAL_CONTEXT_FACTORY,
                "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("com.sun.jndi.ldap.connect.timeout", TimeoutSettings.getConnectionTimeout()+""); // in ms
        env.put("com.sun.jndi.ldap.read.timeout", TimeoutSettings.getConnectionTimeout()+""); // in ms
        env.put(Context.PROVIDER_URL, getUrlPrefix() + host + ":" + port + "/");

        LdapContext ctx = null;
        StartTlsResponse tls = null;
        try {
            try {
                // create initial context
                ctx = new InitialLdapContext(env, null);
                // create the STARTTLS handler object
                tls = (StartTlsResponse) ctx.extendedOperation(new StartTlsRequest());
            } catch (Exception e) {
                throw e;
            }

            // start TLS
            try {
                tls.negotiate(new SavingSSLSocketFactory());
            } catch (SSLHandshakeException e) {
                // likely got an unknown certificate, just report it and return
                // success
                LOG.error("ERROR on IMAP authentication: "
                        + e.toString());
                return true;
            } catch (Exception e) {
                throw e;
            }
        } catch (Exception ex){
            LOG.error(ex.getMessage());
        }finally {
            // stop TLS
            if (tls != null) {
                try {
                    tls.close();
                } catch (IOException e) {
                    LOG.debug(e.getMessage(), e);
                }
            }

            if (ctx != null) // close the context
            {
                try {
                    ctx.close();
                } catch (NamingException e) {
                    LOG.debug(e.getMessage(), e);
                }
            }
        }

        return false;
    }// run
} // class StarttlsHandlerLDAP
