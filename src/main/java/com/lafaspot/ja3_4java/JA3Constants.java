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
	 * Constant for the value 4.
	 */
	public static final int FOUR = 4;
	/**
	 * Constant value 3.
	 */
	public static final int THREE = 3;
	/**
	 * Constant value 8.
	 */
	public static final int EIGHT = 8;
	/**
	 * 
	 */
	public static final int SIXTEEN = 16;
	/**
	 * Constant value for new line.
	 */
	public static final byte NEWLINE = 0x0a;
	/**
	 * Constant value for vertical tab.
	 */
	public static final byte VERTICALTAB = 0x0b;
	/**
	 * 
	 */
	public static final int BITMASK = 0xFF;
    /**
     * Private constructor so that class is not initialized.
     */
    private JA3Constants() {

    }

}

