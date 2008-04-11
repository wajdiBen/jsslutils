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

package jsslutils.sslcontext;

import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * This class is a factory that provides methods for creating an SSLContext
 *  configured with the settings set in this factory: using the SunX509
 *  algorithm for both the key manager and the trust manager. These managers
 *  are created from the KeyStores passed to the constructor.
 *  Unlike the PKIX implementation, this implementation does not support CRLs.
 * 
 * @author Bruno Harbulot
 * 
 */
public class TrustAllClientsX509SSLContextFactory extends X509SSLContextFactory {	
	/**
	 * Builds an SSLContextFactory using the SunX509 algorithm in the 
	 *  TrustManagerFactory.
	 * @param keyStore KeyStore that contains the key.
	 * @param keyPassword password to the key.
	 * @param trustStore KeyStore that contains the trusted X.509 certificates.
	 */
	public TrustAllClientsX509SSLContextFactory(KeyStore keyStore, String keyPassword, KeyStore trustStore) {
		super(keyStore, keyPassword, trustStore);
	}
	
	/**
	 * @return SunX509-based trust managers corresponding to the trust store.
	 */
	@Override
	public TrustManager[] getTrustManagers() throws SSLContextFactoryException {
		TrustManager[] trustManagers = super.getTrustManagers();
		for (int i = 0; i < trustManagers.length; i++) {
			if (trustManagers[i] instanceof X509TrustManager) {
				trustManagers[i] = new TrustAllClientsX509TrustManager((X509TrustManager)trustManagers[i]);
			}
		}
		return trustManagers;
	}
	
	public static class TrustAllClientsX509TrustManager implements X509TrustManager {
		private X509TrustManager trustManager;
		public TrustAllClientsX509TrustManager(X509TrustManager trustManager) {
			this.trustManager = trustManager;
		}
		
		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
		}
		
		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			this.trustManager.checkServerTrusted(chain, authType);
		}
		
		public X509Certificate[] getAcceptedIssuers() {
			return new X509Certificate[0];
		}
	}
}
