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

package org.jsslutils.sslcontext.trustmanagers;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.jsslutils.sslcontext.X509WrappingTrustManager;

/**
 * TrustManager that accepts GSI proxy certificates (clients). The aim is to
 * follow RFC 3820; the current implementation is not strict enough.
 * 
 * @author Bruno Harbulot.
 */
public class GsiWrappingTrustManager extends X509WrappingTrustManager {
	/**
	 * Creates a new instance from an existing X509TrustManager.
	 * 
	 * @param trustManager
	 *            X509TrustManager to wrap.
	 */
	public GsiWrappingTrustManager(X509TrustManager trustManager) {
		super(trustManager);
	}

	/**
	 * Checks that the client is trusted; the aim is to follow RFC 3820.
	 */
	public void checkClientTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		int nonCACertIndex = chain.length - 1;
		/*
		 * Find the first X509Certificate in the chain that is not a CA.
		 */
		for (; nonCACertIndex >= 0; nonCACertIndex--) {
			X509Certificate cert = chain[nonCACertIndex];
			if (cert.getBasicConstraints() == -1) {
				break;
			}
		}

		/*
		 * Test the first non-CA certificate with the default method.
		 */
		X509Certificate[] normalChain = new X509Certificate[chain.length
				- nonCACertIndex];
		for (int i = nonCACertIndex; i < chain.length; i++) {
			normalChain[i - nonCACertIndex] = chain[i];
		}
		this.trustManager.checkClientTrusted(normalChain, authType);

		/*
		 * Walk through the rest of the chain to check that the subsequent
		 * certificates are GSI proxies.
		 */
		boolean prevIsLimited = false;

		X509Certificate cert = chain[nonCACertIndex];

		X500Principal certSubjectPrincipal = cert.getSubjectX500Principal();
		X500Principal certIssuerPrincipal = cert.getIssuerX500Principal();
		String subjectDN = certSubjectPrincipal.getName(X500Principal.RFC2253);
		String issuerDN = certIssuerPrincipal.getName(X500Principal.RFC2253);

		for (int i = nonCACertIndex - 1; i >= 0; i--) {
			X509Certificate prevCert = cert;
			X500Principal prevCertSubjectPrincipal = certSubjectPrincipal;

			cert = chain[i];
			certSubjectPrincipal = cert.getSubjectX500Principal();
			certIssuerPrincipal = cert.getIssuerX500Principal();

			subjectDN = certSubjectPrincipal.getName(X500Principal.RFC2253);
			issuerDN = certIssuerPrincipal.getName(X500Principal.RFC2253);

			/*
			 * Check the time validity of the current certificate.
			 */
			cert.checkValidity();

			try {
				cert.verify(prevCert.getPublicKey());
			} catch (InvalidKeyException e) {
				throw new CertificateException("Failed to verify certificate '"
						+ subjectDN
						+ "' issued by '"
						+ issuerDN
						+ "' with public key from '"
						+ prevCertSubjectPrincipal
								.getName(X500Principal.RFC2253) + "'.", e);
			} catch (NoSuchAlgorithmException e) {
				throw new CertificateException("Failed to verify certificate '"
						+ subjectDN
						+ "' issued by '"
						+ issuerDN
						+ "' with public key from '"
						+ prevCertSubjectPrincipal
								.getName(X500Principal.RFC2253) + "'.", e);
			} catch (NoSuchProviderException e) {
				throw new CertificateException("Failed to verify certificate '"
						+ subjectDN
						+ "' issued by '"
						+ issuerDN
						+ "' with public key from '"
						+ prevCertSubjectPrincipal
								.getName(X500Principal.RFC2253) + "'.", e);
			} catch (SignatureException e) {
				throw new CertificateException("Failed to verify certificate '"
						+ subjectDN
						+ "' issued by '"
						+ issuerDN
						+ "' with public key from '"
						+ prevCertSubjectPrincipal
								.getName(X500Principal.RFC2253) + "'.", e);
			}

			if (prevIsLimited) {
				throw new CertificateException("Previous proxy is limited!");
			}

			if (!subjectDN.endsWith(issuerDN)) {
				throw new CertificateException(
						"Proxy subject DN must end with issuer DN, got '"
								+ subjectDN + "'!");
			}

			/*
			 * New-style proxies must start with CN=<a number>, old-style ones
			 * use CN=proxy or CN=limited proxy
			 */
			if (!subjectDN.startsWith("CN=")) {
				throw new CertificateException(
						"Proxy must start with 'CN=', got '" + subjectDN + "'!");
			}

			if (subjectDN.startsWith("CN=limited proxy")) {
				prevIsLimited = true;
			}
		}
	}
}