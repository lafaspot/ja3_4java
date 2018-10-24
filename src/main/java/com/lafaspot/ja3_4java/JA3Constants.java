package com.lafaspot.ja3_4java;

/**
 *
 * Encapsulation for JA3Constants.
 *
 *
 */
public final class JA3Constants {

    /**
     * Name of the SSLSession's application layer data binding for JA3 Digest value for the session.
     *
     * Example usage:
     *
     * <pre>
     * {
     *     &#064;code
     *     String ja3Digest = sslSession.getValue(JA3Constants.JA3_FINGERPRINT);
     * }
     * </pre>
     *
     * @see javax.net.ssl.SSLSession#getValue(String)
     */
    public static final String JA3_FINGERPRINT = "ja3.digest";

    /**
     * Private constructor so that class is not initialized.
     */
    private JA3Constants() {

    }

}

