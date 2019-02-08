/**
 *  Copyright 2019, Oath Inc.
 *  Licensed under the terms of the Apache 2.0 license.
 *  See LICENSE file in {@link https://github.com/lafaspot/ja3_4java/blob/master/LICENSE} for terms.
 */
package com.lafaspot.ja3_4java;


import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLSession;

import org.mockito.Mockito;
import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Test class for {@link JA3SSLEngineWrapper}.
 *
 */
public class JA3SSLEngineWrapperTest {
    /**
     * Test that methods are executed on the wrapped {@link SSLEngine}.
     * 
     * @throws Exception not expected.
     */
    @Test
    public void testSimpleWrappedMethods() throws Exception {

        SSLEngine engine = Mockito.mock(SSLEngine.class);
        Runnable runnable = Mockito.mock(Runnable.class);
        SSLSession session = Mockito.mock(SSLSession.class);
        String[] supportedCipherSuites = new String[] { "random" };
        String[] enabledCipherSuites = new String[] { "enabled" };
        String[] enabledProtocols = new String[] { "enabled protocols" };
        String[] supportedProtocols = new String[] { "supported protocols" };
        Mockito.doReturn(session).when(engine).getSession();
        Mockito.doReturn(supportedProtocols).when(engine).getSupportedProtocols();
        Mockito.doReturn(enabledProtocols).when(engine).getEnabledProtocols();
        Mockito.doReturn(runnable).when(engine).getDelegatedTask();
        Mockito.doReturn(supportedCipherSuites).when(engine).getSupportedCipherSuites();
        Mockito.doReturn(enabledCipherSuites).when(engine).getEnabledCipherSuites();
        Mockito.doNothing().when(engine).beginHandshake();
        Mockito.doReturn(false).when(engine).isInboundDone();
        Mockito.doNothing().when(engine).closeOutbound();
        Mockito.doReturn(true).when(engine).isOutboundDone();
        Mockito.doReturn(SSLEngineResult.HandshakeStatus.FINISHED).when(engine).getHandshakeStatus();
        Mockito.doReturn(false).when(engine).getUseClientMode();
        Mockito.doReturn(true).when(engine).getNeedClientAuth();
        Mockito.doReturn(false).when(engine).getWantClientAuth();
        Mockito.doReturn(true).when(engine).getEnableSessionCreation();

        JA3SSLEngineWrapper wrapper = new JA3SSLEngineWrapper(engine);

        wrapper.beginHandshake();
        Assert.assertNotNull(wrapper.getDelegatedTask());
        wrapper.closeInbound();
        Assert.assertFalse(wrapper.isInboundDone());
        wrapper.closeOutbound();
        Assert.assertTrue(wrapper.isOutboundDone());
        Assert.assertNotNull(wrapper.getSupportedCipherSuites());
        Assert.assertNotNull(wrapper.getEnabledCipherSuites());
        wrapper.setEnabledCipherSuites(new String[] {});
        Assert.assertNotNull(wrapper.getSupportedProtocols());
        Assert.assertNotNull(wrapper.getEnabledProtocols());
        wrapper.setEnabledProtocols(new String[] {});
        Assert.assertNotNull(wrapper.getSession());
        Assert.assertEquals(SSLEngineResult.HandshakeStatus.FINISHED, wrapper.getHandshakeStatus());
        wrapper.setUseClientMode(true);
        Assert.assertFalse(wrapper.getUseClientMode());
        wrapper.setNeedClientAuth(false);
        Assert.assertTrue(wrapper.getNeedClientAuth());
        wrapper.setWantClientAuth(true);
        Assert.assertFalse(wrapper.getWantClientAuth());
        wrapper.setEnableSessionCreation(false);
        Assert.assertTrue(wrapper.getEnableSessionCreation());
    }
}

