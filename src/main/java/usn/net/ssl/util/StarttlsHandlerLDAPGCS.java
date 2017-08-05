package usn.net.ssl.util;

/**
 * A {@link StarttlsHandler} implementation for LDAP protocol.
 */
public class StarttlsHandlerLDAPGCS extends StarttlsHandlerLDAPS {

    public StarttlsHandlerLDAPGCS() {
        super();
    }
    
    @Override
     public String getUrlPrefix(){
        return "ldaps://";
    }
} // class StarttlsHandlerLDAP
