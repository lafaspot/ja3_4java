package com.lafaspot.ja3_4java;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.KeyManagementException;
import java.security.SecureRandom;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContextSpi;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

/**
 * JA3 SSLContext Service Provider Proxy for JDK8, JDK9 and JDK10.
 */
class JA3SSLContextSpi extends SSLContextSpi {
    /**
     * SSL Context Service Provider provided by the underlying implementation.
     */
    private final SSLContextSpi original;

    /**
     * Reference to the {@link SSLEngine#engineInit} method.
     */
    private final Method engineInit;

    /**
     * Reference to the {@link SSLEngine#engineGetSocketFactory} method.
     */
    private final Method engineGetSocketFactory;

    /**
     * Reference to the {@link SSLEngine#engineGetServerSocketFactory} method.
     */
    private final Method engineGetServerSocketFactory;

    /**
     * Reference to the {@link SSLEngine#engineCreateSSLEngine} method.
     */
    private final Method engineCreateSSLEngine;

    /**
     * Reference to the {@link SSLEngine#engineCreateSSLEngineArgs} method.
     */
    private final Method engineCreateSSLEngineArgs;

    /**
     * Reference to the {@link SSLEngine#engineGetServerSessionContext} method.
     */
    private final Method engineGetServerSessionContext;

    /**
     * Reference to the {@link SSLEngine#engineGetClientSessionContext} method.
     */
    private final Method engineGetClientSessionContext;

    /**
     * Creates a wrapper for generate JA3 signature.
     * @param original SSL context service provider instantiated by underlying implementation
     */
    public JA3SSLContextSpi(final SSLContextSpi original) {
        this.original = original;
        engineInit = getMethod("engineInit", KeyManager[].class, TrustManager[].class, SecureRandom.class);
        engineGetSocketFactory = getMethod("engineGetSocketFactory");
        engineGetServerSocketFactory = getMethod("engineGetServerSocketFactory");
        engineCreateSSLEngine = getMethod("engineCreateSSLEngine");
        engineCreateSSLEngineArgs = getMethod("engineCreateSSLEngine", String.class, int.class);
        engineGetServerSessionContext = getMethod("engineGetServerSessionContext");
        engineGetClientSessionContext = getMethod("engineGetClientSessionContext");
    }

    @Override
    protected void engineInit(final KeyManager[] keyManagers, final TrustManager[] trustManagers, final SecureRandom secureRandom)
            throws KeyManagementException {
        try {
            engineInit.invoke(original, keyManagers, trustManagers, secureRandom);
        } catch (IllegalAccessException e) {
            throw new IllegalStateException("No access to invoke method: engineInit", e);
        } catch (InvocationTargetException e) {
            if (e.getCause() instanceof KeyManagementException) {
                throw (KeyManagementException) e.getCause();
            }
            throw new IllegalStateException("Could not invoke a method: ", e);
        }
    }

    @Override
    protected SSLSocketFactory engineGetSocketFactory() {
        return (SSLSocketFactory) invoke(engineGetSocketFactory);
    }

    @Override
    protected SSLServerSocketFactory engineGetServerSocketFactory() {
        return (SSLServerSocketFactory) invoke(engineGetServerSocketFactory);
    }

    @Override
    protected SSLEngine engineCreateSSLEngine() {
        return new JA3SSLEngineWrapper((SSLEngine) invoke(engineCreateSSLEngine));
    }

    @Override
    protected SSLEngine engineCreateSSLEngine(final String s, final int i) {
        return new JA3SSLEngineWrapper((SSLEngine) invoke(engineCreateSSLEngineArgs, s, i));
    }

    @Override
    protected SSLSessionContext engineGetServerSessionContext() {
        return (SSLSessionContext) invoke(engineGetServerSessionContext);
    }

    @Override
    protected SSLSessionContext engineGetClientSessionContext() {
        return (SSLSessionContext) invoke(engineGetClientSessionContext);
    }

    /**
     * Invokes the passed in method with the provided arguments.
     * @param method method to be invoked
     * @param args arguments to the method
     * @return response from the invoked method
     */
    private Object invoke(final Method method, final Object... args) {
        try {
            return method.invoke(original, args);
        } catch (IllegalAccessException|InvocationTargetException e) {
            throw new IllegalStateException("Could not invoke a method: " + method.getName(), e);
        }
    }

    /**
     * Retrieves the method reference by name.
     * @param methodName method name
     * @param parameters method parameters to identify the method
     * @return reference to the method
     */
    private Method getMethod(final String methodName, final Class<?>... parameters) {
        try {
            Method m = SSLContextSpi.class.getDeclaredMethod(methodName, parameters);
            m.setAccessible(true);
            return m;
        } catch (NoSuchMethodException e) {
            // This should never really happen
            throw new IllegalArgumentException("Could not find a method: " + methodName, e);
        }
    }

}