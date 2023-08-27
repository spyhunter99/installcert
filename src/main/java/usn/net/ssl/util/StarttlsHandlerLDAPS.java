package usn.net.ssl.util;

/**
 * A {@link StarttlsHandler} implementation for LDAP protocol.
 */
public class StarttlsHandlerLDAPS
        extends StarttlsHandlerLDAP {

    public StarttlsHandlerLDAPS() {
        super();
    }

    @Override
    public String getUrlPrefix() {
        return "ldaps://";
    }

} // class StarttlsHandlerLDAP
