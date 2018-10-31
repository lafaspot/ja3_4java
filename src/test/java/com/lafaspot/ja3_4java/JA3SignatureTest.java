package com.lafaspot.ja3_4java;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Paths;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * Test class for {@link JA3Signature}.
 *
 */
public class JA3SignatureTest {
    private static byte[] openSSL_TLS1;
    private static byte[] openSSL_TLS1_1;
    private static byte[] openSSL_TLS1_2;
    private static byte[] openSSL_SSL3;

    @BeforeClass
    public static void readFiles() throws URISyntaxException, IOException {
        openSSL_TLS1 = Files.readAllBytes(Paths.get(JA3SignatureTest.class.getClassLoader().getResource("openssl-tls1.bin").toURI()));
        openSSL_TLS1_1 = Files.readAllBytes(Paths.get(JA3SignatureTest.class.getClassLoader().getResource("openssl-tls1_1.bin").toURI()));
        openSSL_TLS1_2 = Files.readAllBytes(Paths.get(JA3SignatureTest.class.getClassLoader().getResource("openssl-tls1_2.bin").toURI()));
        openSSL_SSL3 = Files.readAllBytes(Paths.get(JA3SignatureTest.class.getClassLoader().getResource("openssl-ssl3.bin").toURI()));
    }

    @Test
    public void testOpenSSL_SSL3() throws Exception {
        Assert.assertEquals(
                "768,49172-49162-57-56-136-135-49167-49157-53-132-49170-49160-22-19-49165-49155-10-49171-49161-51-50-154-153-69-68-49166-49156-47-150-65-7-49169-49159-49164-49154-5-4-21-18-9-20-17-8-6-3-255,,,",
                new JA3Signature().ja3Signature(ByteBuffer.wrap(openSSL_SSL3)));
    }

    @Test
    public void testOpenSSL_TLS1() throws Exception {
        Assert.assertEquals(
                "769,49172-49162-57-56-136-135-49167-49157-53-132-49170-49160-22-19-49165-49155-10-49171-49161-51-50-154-153-69-68-49166-49156-47-150-65-7-49169-49159-49164-49154-5-4-21-18-9-20-17-8-6-3-255,11-10-35-15,24-23,0-1-2",
                new JA3Signature().ja3Signature(ByteBuffer.wrap(openSSL_TLS1)));
    }

    @Test
    public void testOpenSSL_TLS1_1() throws Exception {
        Assert.assertEquals(
                "770,49172-49162-57-56-136-135-49167-49157-53-132-49170-49160-22-19-49165-49155-10-49171-49161-51-50-154-153-69-68-49166-49156-47-150-65-7-49169-49159-49164-49154-5-4-21-18-9-20-17-8-6-3-255,11-10-35-15,24-23,0-1-2",
                new JA3Signature().ja3Signature(ByteBuffer.wrap(openSSL_TLS1_1)));
    }

    @Test
    public void testOpenSSL_TLS1_2() throws Exception {
        Assert.assertEquals(
                "771,49200-49196-49192-49188-49172-49162-163-159-107-106-57-56-136-135-49202-49198-49194-49190-49167-49157-157-61-53-132-49170-49160-22-19-49165-49155-10-49199-49195-49191-49187-49171-49161-162-158-103-64-51-50-154-153-69-68-49201-49197-49193-49189-49166-49156-156-60-47-150-65-7-49169-49159-49164-49154-5-4-21-18-9-20-17-8-6-3-255,11-10-35-13-15,24-23,0-1-2",
                new JA3Signature().ja3Signature(ByteBuffer.wrap(openSSL_TLS1_2)));
    }

    @Test
    public void testNotHandshake() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[0] = 21;
        Assert.assertNull(new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testPacketUnderflow() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[3] = 12; // 12 << 8
        packet[4] = 34; // + 34
        Assert.assertNull(new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testNotClientHello() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[5] = 0;
        Assert.assertNull(new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testHandshakeLengthUnderflow() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[6] = 1; // 1 << 16
        packet[7] = 0; // + 0 << 8
        packet[8] = 1; // + 1
        Assert.assertNull(new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testCipherLengthMalformed() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[45] = 1;
        Assert.assertNull(new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testHandshakeTypeBufferUnderflow() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[3] = 0;
        packet[4] = 0;
        Assert.assertNull(new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testHandshakeLengthBufferUnderflow() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[3] = 0;
        packet[4] = 1;
        Assert.assertNull(new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testClientVersionBufferUnderflow() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[6] = 0;
        packet[7] = 0;
        packet[8] = 1;
        Assert.assertNull(new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testGreaseCipher() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[46] = 0x0a;
        packet[47] = 0x0a;
        Assert.assertEquals(
                "771,49196-49192-49188-49172-49162-163-159-107-106-57-56-136-135-49202-49198-49194-49190-49167-49157-157-61-53-132-49170-49160-22-19-49165-49155-10-49199-49195-49191-49187-49171-49161-162-158-103-64-51-50-154-153-69-68-49201-49197-49193-49189-49166-49156-156-60-47-150-65-7-49169-49159-49164-49154-5-4-21-18-9-20-17-8-6-3-255,11-10-35-13-15,24-23,0-1-2",
                new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testGreaseExtension() throws Exception {
        byte[] packet = openSSL_TLS1_2.clone();
        packet[216] = 0x7a;
        packet[217] = 0x7a;
        Assert.assertEquals(
                "771,49200-49196-49192-49188-49172-49162-163-159-107-106-57-56-136-135-49202-49198-49194-49190-49167-49157-157-61-53-132-49170-49160-22-19-49165-49155-10-49199-49195-49191-49187-49171-49161-162-158-103-64-51-50-154-153-69-68-49201-49197-49193-49189-49166-49156-156-60-47-150-65-7-49169-49159-49164-49154-5-4-21-18-9-20-17-8-6-3-255,11-10-13-15,24-23,0-1-2",
                new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }

    @Test
    public void testEmptyPacket() throws Exception {
        byte[] packet = new byte[] {};
        Assert.assertNull(new JA3Signature().ja3Signature(ByteBuffer.wrap(packet)));
    }
}
