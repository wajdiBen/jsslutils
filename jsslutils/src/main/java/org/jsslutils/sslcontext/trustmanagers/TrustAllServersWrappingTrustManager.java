/*-----------------------------------------------------------------------

  This file is part of the jSSLutils library.
  
Copyright (c) 2008-2010, The University of Manchester, United Kingdom.
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

package org.jsslutils.sslcontext.trustmanagers;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

import javax.net.ssl.X509TrustManager;

import org.jsslutils.sslcontext.X509TrustManagerWrapper;

/**
 * TrustManager that accepts all server certificates as trusted; BE VERY
 * CAREFUL, THIS WILL MAKE YOUR CONNECTION INSECURE.
 * 
 * @author Bruno Harbulot.
 */
public class TrustAllServersWrappingTrustManager implements X509TrustManager {
	private static final Logger LOGGER = Logger
			.getLogger(TrustAllServersWrappingTrustManager.class.getName());
	private final X509TrustManager trustManager;

	/**
	 * Creates a new instance from an existing X509TrustManager.
	 * 
	 * @param trustManager
	 *            X509TrustManager to wrap.
	 */
	public TrustAllServersWrappingTrustManager(X509TrustManager trustManager) {
		LOGGER
				.warning("Using a TrustAllServersWrappingTrustManager (jSSLutils): don't use this trust manager in production.");
		this.trustManager = trustManager;
	}

	/**
	 * Checks that the client is trusted; in this case, it delegates this check
	 * to the trust manager it wraps
	 */
	public void checkClientTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		this.trustManager.checkClientTrusted(chain, authType);
	}

	/**
	 * Checks that the server is trusted; in this case, it accepts anything.
	 */
	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
	}

	/**
	 * Returns the accepted issuers; in this case, it's an empty array.
	 */
	public X509Certificate[] getAcceptedIssuers() {
		return this.trustManager.getAcceptedIssuers();
	}

	/**
	 * Wrapper factory class that wraps existing X509TrustManagers into
	 * X509TrustManagers that trust any clients.
	 * 
	 * @author Bruno Harbulot.
	 */
	public static class Wrapper implements X509TrustManagerWrapper {
		/**
		 * Builds an X509TrustManager from another X509TrustManager.
		 * 
		 * @param trustManager
		 *            original X509TrustManager.
		 * @return wrapped X509TrustManager.
		 */
		public X509TrustManager wrapTrustManager(X509TrustManager trustManager) {
			return new TrustAllServersWrappingTrustManager(
					(X509TrustManager) trustManager);
		}
	}
}