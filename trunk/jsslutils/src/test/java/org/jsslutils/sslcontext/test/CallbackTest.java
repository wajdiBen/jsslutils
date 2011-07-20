/*-----------------------------------------------------------------------

  This file is part of the jSSLutils library.
  
Copyright (c) 2008-2009, The University of Manchester, United Kingdom.
Copyright (c) 2011, Bruno Harbulot.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the copyright holders nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

  Author........: Bruno Harbulot

-----------------------------------------------------------------------*/

package org.jsslutils.sslcontext.test;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;

import org.jsslutils.sslcontext.PKIXSSLContextFactory;
import org.jsslutils.sslcontext.SSLContextFactory.SSLContextFactoryException;
import org.jsslutils.sslcontext.trustmanagers.ServerCallbackWrappingTrustManager;
import org.jsslutils.sslcontext.trustmanagers.ServerCallbackWrappingTrustManager.CheckServerTrustedCallback;
import org.junit.Test;

/**
 * Tests the SSLContext configured for X.509 without CRLs. It should accept both
 * the "good" and the "bad" certificate.
 * 
 * @author Bruno Harbulot.
 * 
 */
public class CallbackTest extends MiniSslClientServer {
    protected PKIXSSLContextFactory clientSSLContextFactory;
    protected PKIXSSLContextFactory serverSSLContextFactory;

    public static CheckServerTrustedCallback ACCEPTING_CALLBACK = new CheckServerTrustedCallback() {
        public boolean checkServerTrusted(X509Certificate[] chain,
                String authType) {
            System.out
                    .println("Asking whether to trust an unkown certificate: ACCEPTING.");
            return true;
        }
    };

    public static CheckServerTrustedCallback REFUSING_CALLBACK = new CheckServerTrustedCallback() {
        public boolean checkServerTrusted(X509Certificate[] chain,
                String authType) {
            System.out
                    .println("Asking whether to trust an unkown certificate: REFUSING.");
            return false;
        }
    };

    @Test
    public void testInMemoryKeyStoreRefused() throws Exception {
        assertTrue(prepareSSLContextFactories());
        this.clientSSLContextFactory
                .setTrustManagerWrapper(new ServerCallbackWrappingTrustManager.Wrapper(
                        REFUSING_CALLBACK, null));
        assertTrue(!runTest());
        assertTrue(!runTest());
    }

    @Test
    public void testInMemoryKeyStoreAccepted() throws Exception {
        assertTrue(prepareSSLContextFactories());
        this.clientSSLContextFactory
                .setTrustManagerWrapper(new ServerCallbackWrappingTrustManager.Wrapper(
                        ACCEPTING_CALLBACK, null));
        assertTrue(runTest());
        assertTrue(runTest());
    }

    @Test
    public void testBadClient() throws Exception {

    }

    public boolean prepareSSLContextFactories() throws Exception {
        this.clientSSLContextFactory = new PKIXSSLContextFactory();
        this.serverSSLContextFactory = new PKIXSSLContextFactory(
                getServerCertKeyStore(), MiniSslClientServer.KEYSTORE_PASSWORD,
                getCaKeyStore());
        return true;
    }

    public boolean runTest() throws Exception {
        return runTest(clientSSLContextFactory.buildSSLContext(),
                serverSSLContextFactory.buildSSLContext());
    }

    /**
     * This runs the main test: it runs a client and a server.
     * 
     * @param sslClientContext
     *            SSLContext to be used by the client.
     * @param sslServerContext
     *            SSLContext to be used by the server.
     * @return true if the server accepted the SSL certificate.
     * @throws SSLContextFactoryException
     * @throws IOException
     */
    public boolean runTest(SSLContext sslClientContext,
            SSLContext sslServerContext) throws IOException,
            InterruptedException {

        final SSLServerSocket serverSocket = prepareServerSocket(sslServerContext);

        assertNotNull("Server socket not null", serverSocket);
        assertTrue("Server socket is bound", serverSocket.isBound());

        Thread serverThread = runServer(serverSocket);

        Exception clientException = null;

        try {
            clientException = makeClientRequest(sslClientContext);
        } finally {
            synchronized (serverSocket) {
                if (!serverSocket.isClosed())
                    serverSocket.close();
            }
        }
        synchronized (serverSocket) {
            assertTrue(serverSocket.isClosed());
        }

        try {
            serverThread.join();
        } catch (InterruptedException e) {
            e.printStackTrace();
        }

        Throwable serverRequestException = null;
        Future<?> serverRequestFuture = serverRequestsFutures.poll();
        try {
            serverRequestFuture.get();
        } catch (ExecutionException e) {
            serverRequestException = e.getCause();
        }

        System.out.println();
        System.out.println("Server request exception: "
                + serverRequestException);
        System.out.println("Client exception: " + clientException);
        System.out.println("Listening server exception: "
                + this.listeningServerException);

        return clientException == null;
    }
}
