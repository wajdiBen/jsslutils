/*-----------------------------------------------------------------------

  This file is part of the jSSLutils library.
  
Copyright (c) 2008, The University of Manchester, United Kingdom.
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
package org.jsslutils.extra.apachehttpclient.test;

import java.io.IOException;
import java.net.ConnectException;

import javax.net.ssl.SSLContext;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.jsslutils.extra.apachehttpclient.SslContextedSecureProtocolSocketFactory;
import org.jsslutils.sslcontext.test.MiniSslClientServer;

import static org.junit.Assert.*;


/**
 * This class is a small test based on MiniSslClientServer which uses the Apache
 * HTTP client library to make the client request.
 * 
 * @author Bruno Harbulot.
 * 
 */
public abstract class MiniSslApacheClientServerTest extends MiniSslClientServer {
	protected HttpClient httpClient;
	protected SslContextedSecureProtocolSocketFactory secureProtocolSocketFactory;

	public MiniSslApacheClientServerTest() {
		MultiThreadedHttpConnectionManager connectionManager = new MultiThreadedHttpConnectionManager();
		this.httpClient = new HttpClient(connectionManager);
	}

	@Override
	protected void doClientRequest(SSLContext sslClientContext)
			throws IOException {
		this.secureProtocolSocketFactory = new SslContextedSecureProtocolSocketFactory(
				sslClientContext);

		Protocol.registerProtocol("https", new Protocol("https",
				(ProtocolSocketFactory) this.secureProtocolSocketFactory, 443));

		GetMethod method = new GetMethod("https://localhost:" + testPort + "/");
		try {
			int statusCode = httpClient.executeMethod(method);
			assertEquals("Request successful", 200, statusCode);
			method.getResponseBodyAsStream();
		} catch (ConnectException e) {
		}
	}
}