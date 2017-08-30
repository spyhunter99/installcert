/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package usn.net.ssl.util;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.sql.Connection;


import org.postgresql.ds.PGSimpleDataSource;
import org.postgresql.ssl.WrappedFactory;

/**
 *
 * @author AO
 */
public class StarttlsHandlerPOSTGRES implements StarttlsHandler {

    public static class DumperFactory extends WrappedFactory {

        public DumperFactory(String arg) throws GeneralSecurityException {

            _factory = InstallCert.getContext().getSocketFactory();
        }
    }

    @Override
    public boolean run(String host, int port,Socket tunnel) throws Exception {

        try {
            PGSimpleDataSource ds = new PGSimpleDataSource();
            ds.setServerName(host);
            ds.setPortNumber(port);
            ds.setSsl(true);
            ///this.sslContext = InstallCert.getContext();
            ds.setSslfactory(host);
            ds.setSslfactory(DumperFactory.class.getName());
            Connection c = ds.getConnection();
            c.close();
            return true;
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return false;
    }

}
