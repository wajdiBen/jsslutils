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

package org.jsslutils.extra.gsi;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.Set;
import java.util.Vector;

import javax.net.ssl.X509TrustManager;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.jce.X509Principal;
import org.jsslutils.sslcontext.X509TrustManagerWrapper;

/**
 * TrustManager that accepts GSI proxy certificates (clients).
 * 
 * @author Bruno Harbulot.
 */
public class GsiWrappingTrustManager implements X509TrustManager {
	public final static String PRERFC_EXTENSION_OID_STRING = "1.3.6.1.4.1.3536.1.222";
	public final static String RFC3820_EXTENSION_OID_STRING = "1.3.6.1.5.5.7.1.14";
	public final static String KEY_USAGE_EXTENSION_OID_STRING = "2.5.29.15";

	private final X509TrustManager trustManager;
	private final boolean allowLegacy;
	private final boolean allowPreRfc;
	private final boolean allowRfc3820;

	/**
	 * Creates a new instance from an existing X509TrustManager.
	 * 
	 * @param trustManager
	 *            X509TrustManager to wrap.
	 */
	public GsiWrappingTrustManager(X509TrustManager trustManager,
			boolean allowLegacy, boolean allowPreRfc, boolean allowRfc3820) {
		this.trustManager = trustManager;
		this.allowPreRfc = allowPreRfc;
		this.allowLegacy = allowLegacy;
		this.allowRfc3820 = allowRfc3820;
	}

	/**
	 * Checks that the client is trusted; the aim is to follow RFC 3820.
	 */
	public void checkClientTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		int eecCertIndex = chain.length - 1;
		/*
		 * Find the first X509Certificate in the chain that is not a CA.
		 */
		for (; eecCertIndex >= 0; eecCertIndex--) {
			X509Certificate cert = chain[eecCertIndex];
			if (cert.getBasicConstraints() == -1) {
				break;
			}
		}

		/*
		 * Test the first non-CA certificate with the default method.
		 */
		X509Certificate[] normalChain = new X509Certificate[chain.length
				- eecCertIndex];
		for (int i = eecCertIndex; i < chain.length; i++) {
			normalChain[i - eecCertIndex] = chain[i];
		}
		trustManager.checkClientTrusted(normalChain, authType);

		CertificateException exception = verifyProxyCertificate(chain,
				eecCertIndex, this.allowLegacy, this.allowPreRfc,
				this.allowRfc3820, null);
		if (exception != null) {
			throw exception;
		}
	}

	/**
	 * Checks that the server is trusted; in this case, it delegates this check
	 * to the trust manager it wraps.
	 */
	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		this.trustManager.checkServerTrusted(chain, authType);
	}

	/**
	 * Returns the accepted issuers; in this case, it delegates this to the
	 * trust manager it wraps.
	 */
	public X509Certificate[] getAcceptedIssuers() {
		return this.trustManager.getAcceptedIssuers();
	}

	/**
	 * Wrapper factory class that wraps existing X509TrustManagers into
	 * GsiWrappingTrustManagers.
	 * 
	 * @author Bruno Harbulot.
	 */
	public static class Wrapper implements X509TrustManagerWrapper {
		private final boolean allowLegacy;
		private final boolean allowPreRfc;
		private final boolean allowRfc3820;

		public Wrapper() {
			this(true, true, true);
		}

		public Wrapper(boolean allowLegacy, boolean allowPreRfc,
				boolean allowRfc3820) {
			this.allowPreRfc = allowPreRfc;
			this.allowLegacy = allowLegacy;
			this.allowRfc3820 = allowRfc3820;
		}

		/**
		 * Builds an X509TrustManager from another X509TrustManager.
		 * 
		 * @param trustManager
		 *            original X509TrustManager.
		 * @return wrapped X509TrustManager.
		 */
		public X509TrustManager wrapTrustManager(X509TrustManager trustManager) {
			return new GsiWrappingTrustManager((X509TrustManager) trustManager,
					this.allowLegacy, this.allowPreRfc, this.allowRfc3820);
		}
	}

	public static CertificateException verifyProxyCertificate(
			X509Certificate[] chain, int eecCertIndex, Date date) {
		return verifyProxyCertificate(chain, eecCertIndex, true, true, true,
				date);
	}

	public static CertificateException verifyProxyCertificate(
			X509Certificate[] chain, int eecCertIndex, boolean allowLegacy,
			boolean allowPreRfc, boolean allowRfc3820, Date date) {
		try {
			X509Certificate proxyCert = chain[0];
			X509Principal subjectPrincipal = new X509Principal(proxyCert
					.getSubjectX500Principal().getEncoded());
			@SuppressWarnings("unchecked")
			Vector<DERObjectIdentifier> subjectDnOids = subjectPrincipal
					.getOIDs();
			@SuppressWarnings("unchecked")
			Vector<String> subjectDnValues = subjectPrincipal.getValues();

			int fieldCount = subjectDnOids.size();
			if (!subjectDnOids.get(fieldCount - 1).equals(X509Name.CN)) {
				return new CertificateException(
						"Proxy must start with 'CN=', got '"
								+ X509Name.DefaultSymbols.get(subjectDnOids
										.get(fieldCount - 1)) + "="
								+ subjectDnValues.get(fieldCount - 1) + "'!");
			} else {
				String cn = subjectDnValues.get(fieldCount - 1);
				if ("limited proxy".equals(cn) || "proxy".equals(cn)) {
					if (!allowLegacy) {
						return new CertificateException(
								"Found what could be at best a legacy proxy certificate, not accepted in this configuration: "
										+ subjectPrincipal);
					}
					return verifyLegacyProxyCertificate(chain, eecCertIndex,
							date);
				} else {
					try {
						new BigInteger(cn);
					} catch (NumberFormatException e) {
						return new CertificateException(
								"Not a Pre-RFC or RFC3820 proxy certificate."
										+ subjectPrincipal);
					}
					Set<String> criticalExtensionOIDs = proxyCert
							.getCriticalExtensionOIDs();
					if (criticalExtensionOIDs
							.contains(RFC3820_EXTENSION_OID_STRING)) {
						if (!allowRfc3820) {
							return new CertificateException(
									"Found what could be at best an RFC3820 certificate, not accepted in this configuration: "
											+ subjectPrincipal);
						}
						return verifyRfc3820ProxyCertificate(chain,
								eecCertIndex, date);
					} else if (criticalExtensionOIDs
							.contains(PRERFC_EXTENSION_OID_STRING)) {
						if (!allowPreRfc) {
							return new CertificateException(
									"Found what could be at best a Pre-RFC proxy certificate, not accepted in this configuration: "
											+ subjectPrincipal);
						}
						return verifyPreRfcProxyCertificate(chain,
								eecCertIndex, date);
					} else {
						return new CertificateException(
								"Couldn't find extension OID is what could be a Pre-RFC or RFC3820 proxy certificate: "
										+ criticalExtensionOIDs);
					}
				}
			}
		} catch (IOException e) {
			return new CertificateParsingException(e);
		} catch (ClassCastException e) {
			return new CertificateParsingException(e);
		}
	}

	public static CertificateException verifyLegacyProxyCertificate(
			X509Certificate[] chain, int eecCertIndex, Date date) {
		try {
			/*
			 * Walk through the rest of the chain to check that the subsequent
			 * certificates are GSI proxies.
			 */
			boolean prevIsLimited = false;

			X509Certificate cert = chain[eecCertIndex];

			X509Principal subjectPrincipal = new X509Principal(cert
					.getSubjectX500Principal().getEncoded());
			@SuppressWarnings("unchecked")
			Vector<DERObjectIdentifier> subjectDnOids = subjectPrincipal
					.getOIDs();
			@SuppressWarnings("unchecked")
			Vector<String> subjectDnValues = subjectPrincipal.getValues();

			for (int i = eecCertIndex - 1; i >= 0; i--) {
				if (prevIsLimited) {
					return new CertificateException(
							"Previous proxy is limited!");
				}

				X509Certificate prevCert = cert;
				X509Principal prevCertSubjectPrincipal = subjectPrincipal;

				cert = chain[i];
				subjectPrincipal = new X509Principal(cert
						.getSubjectX500Principal().getEncoded());
				X509Principal issuerPrincipal = new X509Principal(cert
						.getIssuerX500Principal().getEncoded());

				/*
				 * Verify the issuer's name.
				 */
				if (!issuerPrincipal.equals(prevCertSubjectPrincipal)) {
					return new CertificateException(
							"Issuer's Subject DN doesn't match Issuer DN.");
				}

				Vector<DERObjectIdentifier> issuerDnOids = subjectDnOids;
				Vector<String> issuerDnValues = subjectDnValues;

				@SuppressWarnings("unchecked")
				Vector<DERObjectIdentifier> uncheckedSubjectDnOids = subjectPrincipal
						.getOIDs();
				@SuppressWarnings("unchecked")
				Vector<String> uncheckedSubjectDnValues = subjectPrincipal
						.getValues();
				subjectDnOids = uncheckedSubjectDnOids;
				subjectDnValues = uncheckedSubjectDnValues;

				/*
				 * Verify all issuer's DN fields.
				 */

				int fieldCount = subjectDnOids.size();
				if (!subjectDnOids.get(fieldCount - 1).equals(X509Name.CN)) {
					return new CertificateException(
							"Proxy must start with 'CN=', got '"
									+ X509Name.DefaultSymbols.get(subjectDnOids
											.get(fieldCount - 1)) + "="
									+ subjectDnValues.get(fieldCount - 1)
									+ "'!");
				}
				String cn = subjectDnValues.get(fieldCount - 1);
				if ("limited proxy".equals(cn)) {
					prevIsLimited = true;
				} else if (!"proxy".equals(cn)) {
					return new CertificateException(
							"Legacy proxy certificate Subject DN must start with 'CN=proxy' or 'CN=limited proxy', got 'CN="
									+ cn + "'!");
				}

				if (issuerDnOids.size() != subjectDnOids.size() - 1) {
					return new CertificateException(
							"Subject DN must extend the Issuer DN by one field.");
				}
				for (int j = 0; j < issuerDnOids.size(); j++) {
					if (!issuerDnOids.get(j).equals(subjectDnOids.get(j))) {
						return new CertificateException(
								"Mismatch in Subject DN extension of Issuer DN.");
					}
					if (!issuerDnValues.get(j).equals(subjectDnValues.get(j))) {
						return new CertificateException(
								"Mismatch in Subject DN extension of Issuer DN.");
					}
				}

				/*
				 * Check the time validity of the current certificate.
				 */
				if (date != null) {
					cert.checkValidity(date);
				} else {
					cert.checkValidity();
				}

				/*
				 * Check signature.
				 */
				try {
					cert.verify(prevCert.getPublicKey());
				} catch (InvalidKeyException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				} catch (NoSuchAlgorithmException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				} catch (NoSuchProviderException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				} catch (SignatureException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				}
			}
			return null;
		} catch (CertificateException e) {
			return e;
		} catch (IOException e) {
			return new CertificateParsingException(e);
		}
	}

	public static CertificateException verifyPreRfcProxyCertificate(
			X509Certificate[] chain, int eecCertIndex, Date date) {
		try {
			X509Certificate cert = chain[eecCertIndex];

			X509Principal subjectPrincipal = new X509Principal(cert
					.getSubjectX500Principal().getEncoded());
			@SuppressWarnings("unchecked")
			Vector<DERObjectIdentifier> subjectDnOids = subjectPrincipal
					.getOIDs();
			@SuppressWarnings("unchecked")
			Vector<String> subjectDnValues = subjectPrincipal.getValues();

			for (int i = eecCertIndex - 1; i >= 0; i--) {
				X509Certificate prevCert = cert;
				X509Principal prevCertSubjectPrincipal = subjectPrincipal;

				cert = chain[i];
				subjectPrincipal = new X509Principal(cert
						.getSubjectX500Principal().getEncoded());
				X509Principal issuerPrincipal = new X509Principal(cert
						.getIssuerX500Principal().getEncoded());

				/*
				 * Check the time validity of the current certificate.
				 */
				if (date != null) {
					cert.checkValidity(date);
				} else {
					cert.checkValidity();
				}

				/*
				 * Check signature.
				 */
				try {
					cert.verify(prevCert.getPublicKey());
				} catch (InvalidKeyException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				} catch (NoSuchAlgorithmException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				} catch (NoSuchProviderException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				} catch (SignatureException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				}

				/*
				 * Verify the issuer's name.
				 */
				if (!issuerPrincipal.equals(prevCertSubjectPrincipal)) {
					return new CertificateException(
							"Issuer's Subject DN doesn't match Issuer DN.");
				}

				/*
				 * Assuming same as RFC here.
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.1
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.6
				 */
				boolean[] issuerKeyUsage = prevCert.getKeyUsage();
				if (issuerKeyUsage != null) {
					if (!issuerKeyUsage[0]) {
						return new CertificateException(
								"Proxy issuer has KeyUsage extension but Digital Signature not set!");
					}
				}

				/*
				 * Verifying subject.
				 */
				Vector<DERObjectIdentifier> issuerDnOids = subjectDnOids;
				Vector<String> issuerDnValues = subjectDnValues;

				@SuppressWarnings("unchecked")
				Vector<DERObjectIdentifier> uncheckedSubjectDnOids = subjectPrincipal
						.getOIDs();
				@SuppressWarnings("unchecked")
				Vector<String> uncheckedSubjectDnValues = subjectPrincipal
						.getValues();
				subjectDnOids = uncheckedSubjectDnOids;
				subjectDnValues = uncheckedSubjectDnValues;

				/*
				 * Verify all issuer's DN fields.
				 */
				int fieldCount = subjectDnOids.size();
				if (!subjectDnOids.get(fieldCount - 1).equals(X509Name.CN)) {
					return new CertificateException(
							"Proxy must start with 'CN=', got '"
									+ X509Name.DefaultSymbols.get(subjectDnOids
											.get(fieldCount - 1)) + "="
									+ subjectDnValues.get(fieldCount - 1)
									+ "'!");
				}
				String cn = subjectDnValues.get(fieldCount - 1);
				try {
					new BigInteger(cn);
				} catch (NumberFormatException e) {
					return new CertificateException(
							"Pre-RFC proxy certificate must start with 'CN=<some number>', got 'CN="
									+ cn + "'!");
				}

				if (issuerDnOids.size() != subjectDnOids.size() - 1) {
					return new CertificateException(
							"Subject DN must extend the Issuer DN by one field.");
				}
				for (int j = 0; j < issuerDnOids.size(); j++) {
					if (!issuerDnOids.get(j).equals(subjectDnOids.get(j))) {
						return new CertificateException(
								"Mismatch in Subject DN extension of Issuer DN.");
					}
					if (!issuerDnValues.get(j).equals(subjectDnValues.get(j))) {
						return new CertificateException(
								"Mismatch in Subject DN extension of Issuer DN.");
					}
				}

				/*
				 * Verify proxy extensions.
				 */
				Set<String> criticalExtensionOIDs = cert
						.getCriticalExtensionOIDs();
				if (criticalExtensionOIDs
						.contains(KEY_USAGE_EXTENSION_OID_STRING)) {
					criticalExtensionOIDs
							.remove(KEY_USAGE_EXTENSION_OID_STRING);
				}
				if (criticalExtensionOIDs.contains(PRERFC_EXTENSION_OID_STRING)) {
					criticalExtensionOIDs.remove(PRERFC_EXTENSION_OID_STRING);
					byte[] proxyCertInfoExtension = cert
							.getExtensionValue(PRERFC_EXTENSION_OID_STRING);

					ASN1InputStream asn1InputStream = new ASN1InputStream(
							proxyCertInfoExtension);
					DERObject derObject = asn1InputStream.readObject();
					asn1InputStream.close();

					/*
					 * Read the extension, which is stored as an OCTET STRING.
					 */
					if (derObject instanceof ASN1OctetString) {
						ASN1OctetString proxyCertInfoOctetString = (ASN1OctetString) derObject;
						asn1InputStream = new ASN1InputStream(
								proxyCertInfoOctetString.getOctetStream());
						derObject = asn1InputStream.readObject();
						asn1InputStream.close();

						/*
						 * This must be a SEQUENCE.
						 */
						if (derObject instanceof ASN1Sequence) {
							ASN1Sequence proxyCertInfoSeq = (ASN1Sequence) derObject;
							@SuppressWarnings("unchecked")
							Enumeration<ASN1Object> proxyCertInfoSeqEnum = proxyCertInfoSeq
									.getObjects();
							if (!proxyCertInfoSeqEnum.hasMoreElements()) {
								return new CertificateException(
										"Invalid Pre-RFC ProxyCertInfo extension in this certificate.");
							}
							ASN1Object proxyCertInfoObj = proxyCertInfoSeqEnum
									.nextElement();

							/*
							 * This must be a sequence for the proxy policy.
							 */
							if (proxyCertInfoObj instanceof ASN1Sequence) {
								ASN1Sequence proxyPolicySeq = (ASN1Sequence) proxyCertInfoObj;
								@SuppressWarnings("unchecked")
								Enumeration<ASN1Object> proxyPolicySeqEnum = proxyPolicySeq
										.getObjects();
								if (!proxyPolicySeqEnum.hasMoreElements()) {
									return new CertificateException(
											"Invalid Pre-RFC ProxyCertInfo extension in this certificate.");
								}
								ASN1Object proxyPolicyObj = proxyPolicySeqEnum
										.nextElement();
								/*
								 * The first element is mandatory and it must be
								 * an OBJECT IDENTIFIER (policyLanguage).
								 */
								if (!(proxyPolicyObj instanceof DERObjectIdentifier)) {
									return new CertificateException(
											"Invalid Pre-RFC ProxyCertInfo extension in this certificate.");
								}
								if (proxyPolicySeqEnum.hasMoreElements()) {
									proxyPolicyObj = proxyPolicySeqEnum
											.nextElement();
									/*
									 * The second element is optional, but if
									 * present, it must be an OCTET STRING.
									 */
									if (!(proxyPolicyObj instanceof DEROctetString)) {
										return new CertificateException(
												"Invalid Pre-RFC ProxyCertInfo extension in this certificate.");
									}
								}
								/*
								 * This sequence must not have more elements.
								 */
								if (proxyPolicySeqEnum.hasMoreElements()) {
									return new CertificateException(
											"Invalid Pre-RFC ProxyCertInfo extension in this certificate.");
								}

								if (proxyCertInfoSeqEnum.hasMoreElements()) {
									proxyCertInfoObj = proxyCertInfoSeqEnum
											.nextElement();
								}
							}

							/*
							 * The first element of this sequence may be an
							 * INTEGER, in which case it's pCPathLenConstraint.
							 */
							if (proxyCertInfoObj instanceof DERInteger) {
								DERInteger pCPathLenConstraint = (DERInteger) proxyCertInfoObj;
								BigInteger pathLength = pCPathLenConstraint
										.getValue();
								/*
								 * Check that there are fewer certificates left
								 * to verify in the chain than the authorised
								 * path length.
								 */
								if (pathLength.compareTo(BigInteger.valueOf(i)) < 0) {
									return new CertificateException(
											"Invalid path length delegation.");
								}
							}
							/*
							 * This sequence must not have more elements.
							 */
							if (proxyCertInfoSeqEnum.hasMoreElements()) {
								return new CertificateException(
										"Invalid Pre-RFC ProxyCertInfo extension in this certificate.");
							}
						} else {
							return new CertificateException(
									"Invalid Pre-RFC ProxyCertInfo extension in this certificate.");
						}
					} else {
						return new CertificateException(
								"Invalid Pre-RFC ProxyCertInfo extension in this certificate.");
					}
				} else {
					return new CertificateException(
							"No Pre-RFC ProxyCertInfo extension found in this certificate (must be critical).");
				}

				if (!criticalExtensionOIDs.isEmpty()) {
					return new CertificateCriticalExtensionsNotSupported(
							"Unknown critical extensions.",
							criticalExtensionOIDs);
				}
			}
			return null;
		} catch (CertificateException e) {
			return e;
		} catch (IOException e) {
			return new CertificateParsingException(e);
		}
	}

	public static CertificateException verifyRfc3820ProxyCertificate(
			X509Certificate[] chain, int eecCertIndex, Date date) {
		try {
			X509Certificate cert = chain[eecCertIndex];

			X509Principal subjectPrincipal = new X509Principal(cert
					.getSubjectX500Principal().getEncoded());
			@SuppressWarnings("unchecked")
			Vector<DERObjectIdentifier> subjectDnOids = subjectPrincipal
					.getOIDs();
			@SuppressWarnings("unchecked")
			Vector<String> subjectDnValues = subjectPrincipal.getValues();

			for (int i = eecCertIndex - 1; i >= 0; i--) {
				X509Certificate prevCert = cert;
				X509Principal prevCertSubjectPrincipal = subjectPrincipal;

				cert = chain[i];
				subjectPrincipal = new X509Principal(cert
						.getSubjectX500Principal().getEncoded());
				X509Principal issuerPrincipal = new X509Principal(cert
						.getIssuerX500Principal().getEncoded());

				/*
				 * Check the time validity of the current certificate.
				 */
				if (date != null) {
					cert.checkValidity(date);
				} else {
					cert.checkValidity();
				}

				/*
				 * Check signature.
				 */
				try {
					cert.verify(prevCert.getPublicKey());
				} catch (InvalidKeyException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				} catch (NoSuchAlgorithmException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				} catch (NoSuchProviderException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				} catch (SignatureException e) {
					return new CertificateException(
							"Failed to verify certificate '" + subjectPrincipal
									+ "' issued by '" + issuerPrincipal + "'.",
							e);
				}

				Vector<DERObjectIdentifier> issuerDnOids = subjectDnOids;
				Vector<String> issuerDnValues = subjectDnValues;

				@SuppressWarnings("unchecked")
				Vector<DERObjectIdentifier> uncheckedSubjectDnOids = subjectPrincipal
						.getOIDs();
				@SuppressWarnings("unchecked")
				Vector<String> uncheckedSubjectDnValues = subjectPrincipal
						.getValues();
				subjectDnOids = uncheckedSubjectDnOids;
				subjectDnValues = uncheckedSubjectDnValues;

				/*
				 * Verify that the issuer's DN isn't empty.
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.1
				 */
				if (issuerDnOids.size() <= 0) {
					return new CertificateException(
							"Proxy must not not have empty DN!");
				}

				/*
				 * Verify the issuer's name.
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.1
				 */
				if (!issuerPrincipal.equals(prevCertSubjectPrincipal)) {
					return new CertificateException(
							"Issuer's Subject DN doesn't match Issuer DN.");
				}

				/*
				 * Check Digital Signature bit of issuer.
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.1
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.6
				 */
				boolean[] issuerKeyUsage = prevCert.getKeyUsage();
				if (issuerKeyUsage != null) {
					if (!issuerKeyUsage[0]) {
						return new CertificateException(
								"Proxy issuer has KeyUsage extension but Digital Signature not set!");
					}
				}

				/*
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.2
				 */
				if (cert.getIssuerAlternativeNames() != null) {
					return new CertificateException(
							"Proxy cert must not have an issuer alternative name <http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.2>");
				}

				/*
				 * Verify all issuer's DN fields.
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.3
				 */
				int fieldCount = subjectDnOids.size();
				if (!subjectDnOids.get(fieldCount - 1).equals(X509Name.CN)) {
					return new CertificateException(
							"Proxy must start with 'CN=', got '"
									+ X509Name.DefaultSymbols.get(subjectDnOids
											.get(fieldCount - 1)) + "="
									+ subjectDnValues.get(fieldCount - 1)
									+ "'!");
				}
				String cn = subjectDnValues.get(fieldCount - 1);
				try {
					new BigInteger(cn);
				} catch (NumberFormatException e) {
					return new CertificateException(
							"RFC3820 proxy certificate must start with 'CN=<some number>', got 'CN="
									+ cn + "'!");
				}

				if (issuerDnOids.size() != subjectDnOids.size() - 1) {
					return new CertificateException(
							"Subject DN must extend the Issuer DN by one field.");
				}
				for (int j = 0; j < issuerDnOids.size(); j++) {
					if (!issuerDnOids.get(j).equals(subjectDnOids.get(j))) {
						return new CertificateException(
								"Mismatch in Subject DN extension of Issuer DN.");
					}
					if (!issuerDnValues.get(j).equals(subjectDnValues.get(j))) {
						return new CertificateException(
								"Mismatch in Subject DN extension of Issuer DN.");
					}
				}

				/*
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.5
				 */
				if (cert.getSubjectAlternativeNames() != null) {
					return new CertificateException(
							"Proxy cert must not have a subject alternative name <http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.5>");
				}

				/*
				 * http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.7
				 */
				if (cert.getBasicConstraints() != -1) {
					return new CertificateException(
							"Proxy cert must not CA field in basic constraints extension set to true <http://www.apps.ietf.org/rfc/rfc3820.html#sec-3.7>");
				}

				/*
				 * Verify proxy extensions.
				 */
				Set<String> criticalExtensionOIDs = cert
						.getCriticalExtensionOIDs();
				if (criticalExtensionOIDs
						.contains(KEY_USAGE_EXTENSION_OID_STRING)) {
					criticalExtensionOIDs
							.remove(KEY_USAGE_EXTENSION_OID_STRING);
				}
				if (criticalExtensionOIDs
						.contains(RFC3820_EXTENSION_OID_STRING)) {
					criticalExtensionOIDs.remove(RFC3820_EXTENSION_OID_STRING);
					byte[] proxyCertInfoExtension = cert
							.getExtensionValue(RFC3820_EXTENSION_OID_STRING);

					ASN1InputStream asn1InputStream = new ASN1InputStream(
							proxyCertInfoExtension);
					DERObject derObject = asn1InputStream.readObject();
					asn1InputStream.close();

					/*
					 * Read the extension, which is stored as an OCTET STRING.
					 * See http://tools.ietf.org/html/rfc3820#section-3.8
					 */
					if (derObject instanceof ASN1OctetString) {
						ASN1OctetString proxyCertInfoOctetString = (ASN1OctetString) derObject;
						asn1InputStream = new ASN1InputStream(
								proxyCertInfoOctetString.getOctetStream());
						derObject = asn1InputStream.readObject();
						asn1InputStream.close();

						/*
						 * ProxyCertInfo ::= SEQUENCE { pCPathLenConstraint
						 * INTEGER (0..MAX) OPTIONAL, proxyPolicy ProxyPolicy }
						 * 
						 * This must be a SEQUENCE.
						 */
						if (derObject instanceof ASN1Sequence) {
							ASN1Sequence proxyCertInfoSeq = (ASN1Sequence) derObject;
							@SuppressWarnings("unchecked")
							Enumeration<ASN1Object> proxyCertInfoSeqEnum = proxyCertInfoSeq
									.getObjects();
							if (!proxyCertInfoSeqEnum.hasMoreElements()) {
								return new CertificateException(
										"Invalid RFC3820 ProxyCertInfo extension in this certificate.");
							}
							ASN1Object proxyCertInfoObj = proxyCertInfoSeqEnum
									.nextElement();
							/*
							 * The first element of this sequence may be an
							 * INTEGER, in which case it's pCPathLenConstraint.
							 */
							if (proxyCertInfoObj instanceof DERInteger) {
								DERInteger pCPathLenConstraint = (DERInteger) proxyCertInfoObj;
								BigInteger pathLength = pCPathLenConstraint
										.getValue();
								/*
								 * Check that there are fewer certificates left
								 * to verify in the chain than the authorised
								 * path length.
								 */
								if (pathLength.compareTo(BigInteger.valueOf(i)) < 0) {
									return new CertificateException(
											"Invalid path length delegation.");
								}
								if (!proxyCertInfoSeqEnum.hasMoreElements()) {
									return new CertificateException(
											"Invalid RFC3820 ProxyCertInfo extension in this certificate.");
								}
								proxyCertInfoObj = proxyCertInfoSeqEnum
										.nextElement();
							}
							/*
							 * The following element of this sequence (or the
							 * first one if the first one is not an INTEGER) is
							 * ProxyPolicy ::= SEQUENCE { policyLanguage OBJECT
							 * IDENTIFIER, policy OCTET STRING OPTIONAL }
							 * 
							 * This must be a sequence.
							 */
							if (proxyCertInfoObj instanceof ASN1Sequence) {
								ASN1Sequence proxyPolicySeq = (ASN1Sequence) proxyCertInfoObj;
								@SuppressWarnings("unchecked")
								Enumeration<ASN1Object> proxyPolicySeqEnum = proxyPolicySeq
										.getObjects();
								if (!proxyPolicySeqEnum.hasMoreElements()) {
									return new CertificateException(
											"Invalid RFC3820 ProxyCertInfo extension in this certificate.");
								}
								ASN1Object proxyPolicyObj = proxyPolicySeqEnum
										.nextElement();
								/*
								 * The first element is mandatory and it must be
								 * an OBJECT IDENTIFIER (policyLanguage).
								 */
								if (!(proxyPolicyObj instanceof DERObjectIdentifier)) {
									return new CertificateException(
											"Invalid RFC3820 ProxyCertInfo extension in this certificate.");
								}
								if (proxyPolicySeqEnum.hasMoreElements()) {
									proxyPolicyObj = proxyPolicySeqEnum
											.nextElement();
									/*
									 * The second element is optional, but if
									 * present, it must be an OCTET STRING.
									 */
									if (!(proxyPolicyObj instanceof DEROctetString)) {
										return new CertificateException(
												"Invalid RFC3820 ProxyCertInfo extension in this certificate.");
									}
								}
								/*
								 * This sequence must not have more elements.
								 */
								if (proxyPolicySeqEnum.hasMoreElements()) {
									return new CertificateException(
											"Invalid RFC3820 ProxyCertInfo extension in this certificate.");
								}
							}
							/*
							 * This sequence must not have more elements.
							 */
							if (proxyCertInfoSeqEnum.hasMoreElements()) {
								return new CertificateException(
										"Invalid RFC3820 ProxyCertInfo extension in this certificate.");
							}
						} else {
							return new CertificateException(
									"Invalid RFC3820 ProxyCertInfo extension in this certificate.");
						}
					} else {
						return new CertificateException(
								"Invalid RFC3820 ProxyCertInfo extension in this certificate.");
					}
				} else {
					return new CertificateException(
							"No RFC3820 ProxyCertInfo extension found in this certificate (must be critical).");
				}

				if (!criticalExtensionOIDs.isEmpty()) {
					return new CertificateCriticalExtensionsNotSupported(
							"Unknown critical extensions.",
							criticalExtensionOIDs);
				}
			}
			return null;
		} catch (CertificateException e) {
			return e;
		} catch (IOException e) {
			return new CertificateParsingException(e);
		}
	}

	public static class CertificateCriticalExtensionsNotSupported extends
			CertificateException {
		private static final long serialVersionUID = 1L;
		private final Set<String> unsupportedCriticalExtensionOIDs;

		public CertificateCriticalExtensionsNotSupported() {
			this.unsupportedCriticalExtensionOIDs = null;
		}

		public CertificateCriticalExtensionsNotSupported(
				Set<String> unsupportedCriticalExtensionOIDs) {
			this.unsupportedCriticalExtensionOIDs = Collections
					.unmodifiableSet(unsupportedCriticalExtensionOIDs);
		}

		public CertificateCriticalExtensionsNotSupported(String message,
				Set<String> unsupportedCriticalExtensionOIDs) {
			super(message);
			this.unsupportedCriticalExtensionOIDs = Collections
					.unmodifiableSet(unsupportedCriticalExtensionOIDs);
		}

		public CertificateCriticalExtensionsNotSupported(Throwable throwable,
				Set<String> unsupportedCriticalExtensionOIDs) {
			super(throwable);
			this.unsupportedCriticalExtensionOIDs = Collections
					.unmodifiableSet(unsupportedCriticalExtensionOIDs);
		}

		public CertificateCriticalExtensionsNotSupported(String message,
				Throwable throwable,
				Set<String> unsupportedCriticalExtensionOIDs) {
			super(message, throwable);
			this.unsupportedCriticalExtensionOIDs = Collections
					.unmodifiableSet(unsupportedCriticalExtensionOIDs);
		}

		public Set<String> getUnsupportedCriticalExtensionOIDs() {
			return this.unsupportedCriticalExtensionOIDs;
		}

		public String toString() {
			return super.toString() + " Unknown extensions: "
					+ getUnsupportedCriticalExtensionOIDs();
		}
	}
}