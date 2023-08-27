package usn.net.ssl.util;

/**
 * Adjustable timeout settings
 *
 * @author AO
 */
public class TimeoutSettings {

    //used for connection and socket timeouts
    private static int connectionTimeout = 10000;
    //used for async protocol handlers
    private static int overallTimeout = 15000;

    public static int getConnectionTimeout() {
        return connectionTimeout;
    }

    public static void setConnectionTimeout(int aConnectionTimeout) {
        connectionTimeout = aConnectionTimeout;
    }

    public static int getOverallTimeout() {
        return overallTimeout;
    }

    public static void setOverallTimeout(int aOverallTimeout) {
        overallTimeout = aOverallTimeout;
    }
}
