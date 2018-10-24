package com.lafaspot.ja3_4java;

import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;

/**
 * Generates JA3 signature based on the implementation described at https://github.com/salesforce/ja3.
 *
 */
public final class JA3Signature {
    /**
     * Handshake byte.
     */
    private static final byte HANDSHAKE = 22;
    /**
     * Client hello.
     */
    private static final byte CLIENT_HELLO = 1;
    /**
     * Client hello random lenght.
     */
    private static final byte CLIENT_HELLO_RANDOM_LEN = 32;

    /**
     * Values to account for GREASE (Generate Random Extensions And Sustain Extensibility) as described here:
     * https://tools.ietf.org/html/draft-davidben-tls-grease-01.
     */
    private static final int[] GREASE = new int[] { 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
            0xcaca, 0xdada, 0xeaea, 0xfafa };


    /**
     * Private constructor.
     */
    private JA3Signature() {
        // prevent instantiation
    }

    /**
     * Calculate JA3 string from a ClientHello packet.Note that we do not compute an MD5 hash here.
     *
     * @param packet packet to inspect
     * @return JA3 fingerprint or null if no TLS ClientHello detected in given packet
     * @see <a href="https://github.com/salesforce/ja3">Original JA3 implementation</a>
     */
    public static String ja3Signature(final ByteBuffer packet) {
        // Check there is enough remaining to be able to read TLS record header
        if (packet.remaining() < 4) {
            return null;
        }

        try {
            int end = packet.remaining() + packet.position(); // non-inclusive
            int off = packet.position();

            final byte messageType = getByte(packet, off, end);
            off += 3; // skip TLS Major/Minor

            if (messageType != HANDSHAKE) {
                return null; // not a handshake message
            }

            final int length = getUInt16(packet, off, end);
            off += 2;

            if (end < off + length) {
                return null; // buffer underflow
            }
            // ensure if TLS message length is smaller than packet length, we don't read over
            end = off + length;

            final byte handshakeType = getByte(packet, off, end);
            off++;

            if (handshakeType != CLIENT_HELLO) {
                // log.trace("TLS handshake type not clienthello: {}", handshakeType);
                return null; // not client_hello
            }

            final int handshakeLength = getUInt24(packet, off, end);
            off += 3;

            if (end < off + handshakeLength) {
                return null; // buffer underflow
            }
            // ensure if handShakeLength is smaller than TLS message length, we don't read over
            end = off + handshakeLength;

            final int clientVersion = getUInt16(packet, off, end);
            // Skip random
            off += 2 + CLIENT_HELLO_RANDOM_LEN;

            off += packet.get(off) + 1; // Skip Session ID

            final int cipherSuiteLength = getUInt16(packet, off, end);
            off += 2;

            if (cipherSuiteLength % 2 != 0) {
                return null; // invalid packet, cipher suite length must always be even
            }

            final StringBuilder ja3 = new StringBuilder();

            ja3.append(clientVersion);
            ja3.append(',');

            convertUInt16ArrayToJa3(packet, off, off + cipherSuiteLength, ja3);
            off += cipherSuiteLength;
            ja3.append(',');

            off += packet.get(off) + 3; // Skip Compression Methods and length of extensions

            final StringBuilder ec = new StringBuilder(); // elliptic curves
            final StringBuilder ecpf = new StringBuilder(); // elliptic curve point formats

            parseExtensions(packet, off, end, ja3, ec, ecpf);
            ja3.append(',');

            ja3.append(ec);
            ja3.append(',');

            ja3.append(ecpf);

            String ja3String = ja3.toString();


            return ja3String;
        } catch (BufferUnderflowException | ArrayIndexOutOfBoundsException e) {
            return null;
        }
    }

    /**
     * Parse TLS extensions from given TLS ClientHello packet.
     *
     * @param packet clienthello packet
     * @param off offset to start reading extensions
     * @param packetEnd offset where packet ends
     * @param ei string builder to output the generated ja3 string for extensions identifiers
     * @param ec string builder to output the generated ja3 string for elliptic curves
     * @param ecpf string builder to output the generated ja3 string for elliptic curve points
     */
    private static void parseExtensions(final ByteBuffer packet, int off, final int packetEnd, final StringBuilder ei, final StringBuilder ec,
            final StringBuilder ecpf) {
        boolean first = true;

        while (off < packetEnd) {
            int extensionType = getUInt16(packet, off, packetEnd);
            off += 2;
            int extensionLength = getUInt16(packet, off, packetEnd);
            off += 2;

            if (extensionType == 0x0a) {
                // Elliptic curve points
                int curveListLength = getUInt16(packet, off, packetEnd);
                convertUInt16ArrayToJa3(packet, off + 2, off + 2 + curveListLength, ec);
            } else if (extensionType == 0x0b) {
                // Elliptic curve point formats
                int curveFormatLength = packet.get(off) & 0xFF;
                convertUInt8ArrayToJa3(packet, off + 1, off + 1 + curveFormatLength, ecpf);
            }

            if (isNotGrease(extensionType)) {
                if (!first) {
                    ei.append('-');
                }
                ei.append(extensionType);
                first = false;
            }

            off += extensionLength;
        }
    }

    /**
     * Check if TLS protocols cipher, extension, named groups, signature algorithms and version values match GREASE values. <blockquote
     * cite="https://tools.ietf.org/html/draft-ietf-tls-grease"> GREASE (Generate Random Extensions And Sustain Extensibility), a mechanism to prevent
     * extensibility failures in the TLS ecosystem. It reserves a set of TLS protocol values that may be advertised to ensure peers correctly handle
     * unknown values </blockquote>
     *
     * @param value value to be checked against GREASE values
     * @return false if value matches GREASE value, true otherwise
     * @see <a href="https://tools.ietf.org/html/draft-ietf-tls-grease">draft-ietf-tls-grease</a>
     */
    private static boolean isNotGrease(final int value) {
        for (int i = 0; i < GREASE.length; i++) {
            if (value == GREASE[i]) {
                return false;
            }
        }

        return true;
    }

    /**
     * Convert unsigned 16-bit integer array to JA3 string.
     * <p>
     * Note: This method does not check alignment of the start and end are 2-bytes. The caller is responsible for ensuring a valid 16-bit integer
     * array is provided.
     *
     * @param source packet source
     * @param start start offset of array in packet
     * @param end end offset of array in packet
     * @param out string builder to output the generated JA3 string
     * @throws BufferUnderflowException when source packet does not have enough bytes to read
     */
    private static void convertUInt16ArrayToJa3(final ByteBuffer source, int start, final int end, final StringBuilder out) {
        boolean first = true;
        for (; start < end; start += 2) {
            int value = getUInt16(source, start, end);
            if (isNotGrease(value)) {
                if (!first) {
                    out.append('-');
                }
                out.append(value);
                first = false;
            }
        }
    }

    /**
     * Convert unsigned 8-bit integer array to JA3 string.
     *
     * @param source packet source
     * @param start start offset of array in packet
     * @param end end offset of array in packet
     * @param out string builder to output the generated JA3 string
     * @throws BufferUnderflowException when source packet does not have enough bytes to read
     */
    private static void convertUInt8ArrayToJa3(final ByteBuffer source, int start, final int end, final StringBuilder out) {
        for (; start < end; start++) {
            out.append(getByte(source, start, end));
            if (start < end - 1) {
                out.append('-');
            }
        }
    }

    /**
     * Read unsigned 24-bit integer from a network byte ordered buffer.
     *
     * @param source buffer to read from
     * @param start start offset of integer in buffer
     * @param end end offset of integer in buffer
     * @return unsigned integer
     * @throws BufferUnderflowException when source buffer does not have enough bytes to read
     */
    private static int getUInt24(final ByteBuffer source, final int start, final int end) {
        if (start + 3 > end) {
            throw new BufferUnderflowException();
        }

        return ((source.get(start) & 0xFF) << 16) + ((source.get(start + 1) & 0xFF) << 8) + (source.get(start + 2) & 0xFF);
    }

    /**
     * Read unsigned 16-bit integer from a network byte ordered buffer.
     *
     * @param source buffer to read from
     * @param start start offset of integer in buffer
     * @param end end offset of integer in buffer
     * @return unsigned integer
     * @throws BufferUnderflowException when source buffer does not have enough bytes to read
     */
    private static int getUInt16(final ByteBuffer source, final int start, final int end) {
        if (start + 2 > end) {
            throw new BufferUnderflowException();
        }

        return ((source.get(start) & 0xFF) << 8) + (source.get(start + 1) & 0xFF);
    }

    /**
     * Read a single byte from a network byte ordered buffer.
     *
     * @param source buffer to read from
     * @param start start offset of integer in buffer
     * @param end end offset of integer in buffer
     * @return a byte
     * @throws BufferUnderflowException when source buffer does not have enough bytes to read
     */
    private static byte getByte(final ByteBuffer source, final int start, final int end) {
        if (start + 1 > end) {
            throw new BufferUnderflowException();
        }

        return source.get(start);
    }
}

