package usn.net.ssl.util;

import java.security.GeneralSecurityException;
import org.postgresql.ssl.WrappedFactory;

/**
 *
 * @author AO
 */
public class PostgresDumperFactory extends WrappedFactory {

    public PostgresDumperFactory(String arg) throws GeneralSecurityException {

        factory = InstallCert.getContext().getSocketFactory();
    }
}
