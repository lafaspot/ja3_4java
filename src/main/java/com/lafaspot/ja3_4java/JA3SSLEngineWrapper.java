package com.lafaspot.ja3_4java;

import java.nio.ByteBuffer;
import java.util.Objects;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;

/**
 * This class wraps an SSLEngine and adds JA3 fingerprinting capability to it.
 *
 */
public class JA3SSLEngineWrapper extends SSLEngine {

    /**
     * The {@link SSLEngine} that is wrapped by this class.
     */
    private final SSLEngine engine;

    /**
     * True if the ja3 signature has been set in the ssl session.
     */
    private boolean isJa3SignatureSet = false;
    
    /**
     * Ja3 signature for the client.
     */
    private String ja3 = null;

    /**
     * Wrap an existing SSLEngine to add calculation of JA3 digest.
     *
     * @param engine existing engine
     */
    public JA3SSLEngineWrapper(final SSLEngine engine) {
        Objects.requireNonNull(engine, "null SSLEngine");
        this.engine = engine;
    }

    @Override
    public SSLEngineResult wrap(final ByteBuffer[] srcs, final int offset, final int length, final ByteBuffer dst) throws SSLException {
        return engine.wrap(srcs, offset, length, dst);
    }

    @Override
    public SSLEngineResult unwrap(final ByteBuffer src, final ByteBuffer[] dsts, final int offset, final int length) throws SSLException {
		final SSLEngineResult result;
		if (ja3 == null) {
			//1. Generate JA3 signature
			final HandshakeStatus handshakeStatus = engine.getHandshakeStatus();
			if (HandshakeStatus.FINISHED != handshakeStatus) {
				ja3 = new JA3Signature().ja3Signature(src);
			}
			
			//unwrap
			result = engine.unwrap(src, dsts, offset, length);
		} else if (!isJa3SignatureSet) {
			//2. Set ja3 signature in ssl handshake session
			
			//unwrap
			result = engine.unwrap(src, dsts, offset, length);
			
			final SSLSession handshakeSession = engine.getHandshakeSession();
			if (handshakeSession != null) {
				//set ja3 signature in handshake session
				handshakeSession.putValue(JA3Constants.JA3_FINGERPRINT, ja3);
				isJa3SignatureSet = true;
			}
		} else {
			//3. JA3 Signature is set in the handshake session, call engine.unwrap
			//unwrap
			result = engine.unwrap(src, dsts, offset, length);
		}

		return result;
    }

    /* Wrapped methods */

    @Override
    public void beginHandshake() throws SSLException {
        engine.beginHandshake();
    }

    @Override
    public Runnable getDelegatedTask() {
        return engine.getDelegatedTask();
    }

    @Override
    public void closeInbound() throws SSLException {
        engine.closeInbound();
    }

    @Override
    public boolean isInboundDone() {
        return engine.isInboundDone();
    }

    @Override
    public void closeOutbound() {
        engine.closeOutbound();
    }

    @Override
    public boolean isOutboundDone() {
        return engine.isOutboundDone();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return engine.getSupportedCipherSuites();
    }

    @Override
    public String[] getEnabledCipherSuites() {
        return engine.getEnabledCipherSuites();
    }

    @Override
    public void setEnabledCipherSuites(final String[] strings) {
        engine.setEnabledCipherSuites(strings);
    }

    @Override
    public String[] getSupportedProtocols() {
        return engine.getSupportedProtocols();
    }

    @Override
    public String[] getEnabledProtocols() {
        return engine.getEnabledProtocols();
    }

    @Override
    public void setEnabledProtocols(final String[] strings) {
        engine.setEnabledProtocols(strings);
    }

    @Override
    public SSLSession getSession() {
        return engine.getSession();
    }

    @Override
    public SSLEngineResult.HandshakeStatus getHandshakeStatus() {
        return engine.getHandshakeStatus();
    }

    @Override
    public void setUseClientMode(final boolean b) {
        engine.setUseClientMode(b);
    }

    @Override
    public boolean getUseClientMode() {
        return engine.getUseClientMode();
    }

    @Override
    public void setNeedClientAuth(final boolean b) {
        engine.setNeedClientAuth(b);
    }

    @Override
    public boolean getNeedClientAuth() {
        return engine.getNeedClientAuth();
    }

    @Override
    public void setWantClientAuth(final boolean b) {
        engine.setWantClientAuth(b);
    }

    @Override
    public boolean getWantClientAuth() {
        return engine.getWantClientAuth();
    }

    @Override
    public void setEnableSessionCreation(final boolean b) {
        engine.setEnableSessionCreation(b);
    }

    @Override
    public boolean getEnableSessionCreation() {
        return engine.getEnableSessionCreation();
    }
}
