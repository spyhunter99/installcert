package usn.net.ssl.util;

import java.net.Socket;
import java.sql.Connection;


/**
 *
 * @author AO
 */
public class StarttlsHandlerPOSTGRES implements StarttlsHandler {

    @Override
    public boolean run(String host, int port, Socket tunnel) throws Exception {
        Object ds = null;
        try {
            ds = Class.forName("org.postgresql.ds.PGSimpleDataSource").newInstance();
        } catch (Throwable t) {
            throw new Exception("Unable to classload postgres jdbc driver. Check to ensure it's on the classpath");
        }
        try {

            ds.getClass().getMethod("setServerName", String.class).invoke(ds, host);
            ds.getClass().getMethod("setPortNumber", int.class).invoke(ds, port);
            ds.getClass().getMethod("setSsl", boolean.class).invoke(ds, true);
            ds.getClass().getMethod("setSslfactory", String.class).invoke(ds, "usn.net.ssl.util.PostgresDumperFactory");
            Connection c = (Connection) ds.getClass().getMethod("getConnection").invoke(ds, (Object[]) null);

            c.close();
            return true;
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
        return false;
    }

}
