/*-----------------------------------------------------------------------

  This file is part of the jSSLutils library.
  
Copyright (c) 2008-2009, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the The University of Manchester nor the names of 
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

import static org.junit.Assert.assertTrue;

import org.jsslutils.sslcontext.PKIXSSLContextFactory;
import org.jsslutils.sslcontext.test.MiniSslClientServer;
import org.junit.Test;

/**
 * Tests the SSLContext configured for PKIX with CRLs. It should accept the
 * "good" certificate but reject the "bad" certificate because it has been
 * revoked.
 * 
 * @author Bruno Harbulot.
 * 
 */
public class PKIXNoExplicitCrlTest extends SimpleX509Test {
    @Override
    public boolean prepareSSLContextFactories() throws Exception {
        PKIXSSLContextFactory clientSSLContextFactory = new PKIXSSLContextFactory(
                this.clientStore, MiniSslClientServer.KEYSTORE_PASSWORD,
                getCaKeyStore());
        this.clientSSLContextFactory = clientSSLContextFactory;

        PKIXSSLContextFactory serverSSLContextFactory = new PKIXSSLContextFactory(
                getServerCertKeyStore(), MiniSslClientServer.KEYSTORE_PASSWORD,
                getCaKeyStore());
        this.serverSSLContextFactory = serverSSLContextFactory;

        return true;
    }

    @Test
    public void testGoodClient() throws Exception {
        this.clientStore = getGoodClientCertKeyStore();
        assertTrue("Loaded keystore", true);
        assertTrue(runTest());
    }

    @Test
    public void testBadClient() throws Exception {
        this.clientStore = getBadClientCertKeyStore();
        assertTrue("Loaded keystore", true);
        assertTrue(runTest());
    }
}
