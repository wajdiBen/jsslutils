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

package org.jsslutils.sslcontext.test;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLStreamHandler;
import java.net.URLStreamHandlerFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.cert.CRLException;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Random;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLNumber;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V2CRLGenerator;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.AuthorityKeyIdentifierStructure;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;
import org.jsslutils.sslcontext.PKIXSSLContextFactory;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * Tests the SSLContext configured for PKIX with CRLs. It should accept the
 * "good" certificate but reject the "bad" certificate because it has been
 * revoked.
 * 
 * @author Bruno Harbulot.
 * 
 */
public class PKIXReloadCrlTest extends MiniSslClientServer {

	private X500Principal caName;
	private PublicKey caPublicKey;
	private PrivateKey caPrivateKey;
	private X509Certificate caCertificate;
	private X509Certificate localhostCertificate;
	private X509Certificate client1Certificate;
	private X509Certificate client2Certificate;

	private KeyStore caKeyStore;
	private KeyStore serverKeyStore;
	private KeyStore client1KeyStore;
	private KeyStore client2KeyStore;
	private ArrayList<X509CRL> crls = new ArrayList<X509CRL>();
	private static X509CRL crl;

	static {
		if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
			Security.addProvider(new BouncyCastleProvider());
		}
	}

	public static X509Certificate generateCertificate(X500Principal issuer,
			X500Principal subject, PublicKey issuerPublicKey,
			PrivateKey issuerPrivateKey, PublicKey subjectPublicKey)
			throws Exception {

		X509V3CertificateGenerator certGenerator = new X509V3CertificateGenerator();
		certGenerator.reset();

		certGenerator.setIssuerDN(issuer);
		certGenerator.setSubjectDN(subject);

		Date startDate = new Date(System.currentTimeMillis());
		certGenerator.setNotBefore(startDate);
		Date endDate = new Date(startDate.getTime() + 365L * 24L * 60L * 60L
				* 1000L);
		certGenerator.setNotAfter(endDate);

		Random r = new Random();
		certGenerator.setSerialNumber(new BigInteger(32, r));

		certGenerator.setPublicKey(subjectPublicKey);
		String pubKeyAlgorithm = issuerPublicKey.getAlgorithm();
		if (pubKeyAlgorithm.equals("DSA")) {
			certGenerator.setSignatureAlgorithm("SHA1WithDSA");
		} else if (pubKeyAlgorithm.equals("RSA")) {
			certGenerator.setSignatureAlgorithm("SHA1WithRSAEncryption");
		} else {
			RuntimeException re = new RuntimeException(
					"Algorithm not recognised: " + pubKeyAlgorithm);
			throw re;
		}

		certGenerator.addExtension(X509Extensions.BasicConstraints, true,
				new BasicConstraints(subject.equals(issuer)));

		AuthorityKeyIdentifierStructure authorityKeyIdentifier = new AuthorityKeyIdentifierStructure(
				issuerPublicKey);
		certGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier,
				false, authorityKeyIdentifier);

		SubjectKeyIdentifier subjectKeyIdentifier = new SubjectKeyIdentifierStructure(
				subjectPublicKey);
		certGenerator.addExtension(X509Extensions.SubjectKeyIdentifier, false,
				subjectKeyIdentifier);

		X509Certificate cert = certGenerator.generate(issuerPrivateKey);

		cert.verify(issuerPublicKey);

		return cert;
	}

	public static long crlNumber = 1L;

	public static X509CRL generateCRL(X500Principal issuer,
			Collection<BigInteger> revokedSerialNumbers,
			PublicKey issuerPublicKey, PrivateKey issuerPrivateKey)
			throws Exception {

		X509V2CRLGenerator crlGenerator = new X509V2CRLGenerator();
		crlGenerator.reset();

		crlGenerator.setIssuerDN(issuer);

		Date startDate = new Date(System.currentTimeMillis());
		crlGenerator.setThisUpdate(startDate);
		Date endDate = new Date(startDate.getTime() + 24L * 60L * 60L * 1000L);
		crlGenerator.setNextUpdate(endDate);

		String keyAlgorithm = issuerPrivateKey.getAlgorithm();
		if (keyAlgorithm.equals("DSA")) {
			crlGenerator.setSignatureAlgorithm("SHA1WithDSA");
		} else if (keyAlgorithm.equals("RSA")) {
			crlGenerator.setSignatureAlgorithm("SHA1WithRSAEncryption");
		} else {
			RuntimeException re = new RuntimeException(
					"Algorithm not recognised: " + keyAlgorithm);
			throw re;
		}

		for (BigInteger serialNum : revokedSerialNumbers) {
			crlGenerator.addCRLEntry(serialNum, startDate,
					CRLReason.unspecified);
		}

		crlGenerator.addExtension(X509Extensions.AuthorityKeyIdentifier, false,
				new AuthorityKeyIdentifierStructure(issuerPublicKey));
		crlGenerator.addExtension(X509Extensions.CRLNumber, false,
				new CRLNumber(BigInteger.valueOf(crlNumber++)));

		X509CRL crl = crlGenerator.generate(issuerPrivateKey);

		crl.verify(issuerPublicKey);

		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		return (X509CRL) cf.generateCRL(new ByteArrayInputStream(crl
				.getEncoded()));
	}

	public synchronized static InputStream getCrlInputStream() throws Exception {
		return new ByteArrayInputStream(crl.getEncoded());
	}

	@Before
	public void createTestCertificates() throws Exception {
		KeyPair keyPair;
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

		kpg.initialize(1024);
		keyPair = kpg.genKeyPair();
		caPublicKey = keyPair.getPublic();
		caPrivateKey = keyPair.getPrivate();
		caName = new X500Principal("CN=Root CA, O=Test Certification Authority");
		caCertificate = generateCertificate(caName, caName, caPublicKey,
				caPrivateKey, caPublicKey);
		caKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		caKeyStore.load(null);
		caKeyStore.setCertificateEntry("ca-certificate", caCertificate);

		kpg.initialize(1024);
		keyPair = kpg.genKeyPair();
		X500Principal localhostName = new X500Principal(
				"CN=localhost, O=Test Certification Authority");
		localhostCertificate = generateCertificate(caName, localhostName,
				caPublicKey, caPrivateKey, keyPair.getPublic());
		serverKeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		serverKeyStore.load(null);
		serverKeyStore.setKeyEntry("localhost", keyPair.getPrivate(),
				MiniSslClientServer.KEYSTORE_PASSWORD,
				new Certificate[] { localhostCertificate });

		kpg.initialize(1024);
		keyPair = kpg.genKeyPair();
		X500Principal client1Name = new X500Principal(
				"CN=testclient1, O=Test Certification Authority");
		client1Certificate = generateCertificate(caName, client1Name,
				caPublicKey, caPrivateKey, keyPair.getPublic());
		client1KeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		client1KeyStore.load(null);
		client1KeyStore.setKeyEntry("client1", keyPair.getPrivate(),
				MiniSslClientServer.KEYSTORE_PASSWORD,
				new Certificate[] { client1Certificate });

		kpg.initialize(1024);
		keyPair = kpg.genKeyPair();
		X500Principal client2Name = new X500Principal(
				"CN=testclient2, O=Test Certification Authority");
		client2Certificate = generateCertificate(caName, client2Name,
				caPublicKey, caPrivateKey, keyPair.getPublic());
		client2KeyStore = KeyStore.getInstance(KeyStore.getDefaultType());
		client2KeyStore.load(null);
		client2KeyStore.setKeyEntry("client2", keyPair.getPrivate(),
				MiniSslClientServer.KEYSTORE_PASSWORD,
				new Certificate[] { client2Certificate });
	}

	@BeforeClass
	public static void setupUrlHandler() {
		URLStreamHandlerFactory mockStreamHandlerFactory = new URLStreamHandlerFactory() {
			public URLStreamHandler createURLStreamHandler(String protocol) {
				if ("http".equals(protocol) || "https".equals(protocol)) {
					return new URLStreamHandler() {
						@Override
						protected URLConnection openConnection(final URL u)
								throws IOException {
							return new HttpURLConnection(u) {
								@Override
								public void disconnect() {
								}

								@Override
								public boolean usingProxy() {
									return false;
								}

								@Override
								public void connect() throws IOException {
								}

								@Override
								public String getContentType() {
									return "application/pkix-crl";
								}

								@Override
								public InputStream getInputStream()
										throws IOException {
									try {
										return getCrlInputStream();
									} catch (Exception e) {
										throw new IOException(
												"Exception trying to load " + u,
												e);
									}
								}
							};
						}
					};
				}
				return null;
			}
		};
		URL.setURLStreamHandlerFactory(mockStreamHandlerFactory);
	}

	@Override
	public Collection<X509CRL> getLocalCRLs() throws IOException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException,
			CRLException {
		return crls;
	}

	PKIXSSLContextFactory clientSSLContextFactory;
	PKIXSSLContextFactory serverSSLContextFactory;

	public void prepareServerSSLContextFactory(KeyStore clientStore,
			boolean addLocalCrls) throws Exception {
		clientSSLContextFactory = new PKIXSSLContextFactory(clientStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);

		serverSSLContextFactory = new PKIXSSLContextFactory(serverKeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);

		if (addLocalCrls) {
			clientSSLContextFactory.addCrlCollection(getLocalCRLs());
			serverSSLContextFactory.addCrlCollection(getLocalCRLs());
		}
	}

	public boolean runTest() throws Exception {
		return runTest(clientSSLContextFactory.buildSSLContext(),
				serverSSLContextFactory.buildSSLContext());
	}

	@Test
	public void testWithEmptyCrl() throws Exception {
		this.crls.clear();
		this.crls.add(generateCRL(caName, Arrays.asList(new BigInteger[] {}),
				caPublicKey, caPrivateKey));

		serverSSLContextFactory = new PKIXSSLContextFactory(serverKeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		serverSSLContextFactory.addCrlCollection(getLocalCRLs());

		clientSSLContextFactory = new PKIXSSLContextFactory(client1KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		clientSSLContextFactory.addCrlCollection(getLocalCRLs());
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());

		clientSSLContextFactory = new PKIXSSLContextFactory(client2KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		clientSSLContextFactory.addCrlCollection(getLocalCRLs());
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());
	}

	@Test
	public void testWithNonEmptyCrl() throws Exception {
		this.crls.clear();
		this.crls.add(generateCRL(caName,
				Arrays.asList(new BigInteger[] { client2Certificate
						.getSerialNumber() }), caPublicKey, caPrivateKey));

		serverSSLContextFactory = new PKIXSSLContextFactory(serverKeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		serverSSLContextFactory.addCrlCollection(getLocalCRLs());

		clientSSLContextFactory = new PKIXSSLContextFactory(client1KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		clientSSLContextFactory.addCrlCollection(getLocalCRLs());
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());

		this.crls.clear();
		this.crls.add(generateCRL(caName,
				Arrays.asList(new BigInteger[] { client2Certificate
						.getSerialNumber() }), caPublicKey, caPrivateKey));
		clientSSLContextFactory = new PKIXSSLContextFactory(client2KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		clientSSLContextFactory.addCrlCollection(getLocalCRLs());
		assertTrue("Loaded keystore", true);
		assertTrue(!runTest());
	}

	@Test
	public void testWithRemoteCrlPermanentlyCached() throws Exception {
		X509CRL crl = generateCRL(caName, Arrays.asList(new BigInteger[] {}),
				caPublicKey, caPrivateKey);
		synchronized (PKIXReloadCrlTest.class) {
			PKIXReloadCrlTest.crl = crl;
		}

		serverSSLContextFactory = new PKIXSSLContextFactory(serverKeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		serverSSLContextFactory.addCrl("http://localhost.example/crl");

		clientSSLContextFactory = new PKIXSSLContextFactory(client1KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());

		clientSSLContextFactory = new PKIXSSLContextFactory(client2KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());

		crl = generateCRL(caName,
				Arrays.asList(new BigInteger[] { client2Certificate
						.getSerialNumber() }), caPublicKey, caPrivateKey);
		synchronized (PKIXReloadCrlTest.class) {
			PKIXReloadCrlTest.crl = crl;
		}

		Thread.sleep(5000);
		clientSSLContextFactory = new PKIXSSLContextFactory(client1KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());

		clientSSLContextFactory = new PKIXSSLContextFactory(client2KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());
	}

	@Test
	public void testWithRemoteCrlReloaded() throws Exception {
		X509CRL crl = generateCRL(caName, Arrays.asList(new BigInteger[] {}),
				caPublicKey, caPrivateKey);
		synchronized (PKIXReloadCrlTest.class) {
			PKIXReloadCrlTest.crl = crl;
		}

		serverSSLContextFactory = new PKIXSSLContextFactory(serverKeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		serverSSLContextFactory.addCrl("http://localhost.example/crl", 2);

		clientSSLContextFactory = new PKIXSSLContextFactory(client1KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());

		clientSSLContextFactory = new PKIXSSLContextFactory(client2KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());

		crl = generateCRL(caName,
				Arrays.asList(new BigInteger[] { client2Certificate
						.getSerialNumber() }), caPublicKey, caPrivateKey);
		synchronized (PKIXReloadCrlTest.class) {
			PKIXReloadCrlTest.crl = crl;
		}

		Thread.sleep(5000);
		clientSSLContextFactory = new PKIXSSLContextFactory(client1KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		assertTrue("Loaded keystore", true);
		assertTrue(runTest());

		clientSSLContextFactory = new PKIXSSLContextFactory(client2KeyStore,
				MiniSslClientServer.KEYSTORE_PASSWORD, caKeyStore, true);
		assertTrue("Loaded keystore", true);
		assertTrue(!runTest());
	}

	@Test
	public void testWithRemoteCrlReloadedSameListeningSocket() throws Exception {
		X509CRL crl = generateCRL(caName, Arrays.asList(new BigInteger[] {}),
				caPublicKey, caPrivateKey);
		synchronized (PKIXReloadCrlTest.class) {
			PKIXReloadCrlTest.crl = crl;
		}

		PKIXSSLContextFactory serverSSLContextFactory = new PKIXSSLContextFactory(
				serverKeyStore, MiniSslClientServer.KEYSTORE_PASSWORD,
				caKeyStore, true);
		serverSSLContextFactory.addCrl("http://localhost.example/crl", 2);
		SSLContext sslServerContext = serverSSLContextFactory.buildSSLContext();

		this.serverRequestException = null;
		boolean result = false;
		SSLServerSocket serverSocket = prepareServerSocket(sslServerContext);
		assertNotNull("Server socket not null", serverSocket);
		assertTrue("Server socket is bound", serverSocket.isBound());

		final SSLServerSocket fServerSocket = serverSocket;
		if (fServerSocket != null) {
			setServerRequestNumber(4);
			runServer(fServerSocket);

			try {
				PKIXSSLContextFactory clientSSLContextFactory;
				SSLContext sslClientContext;
				this.serverTimeout = 8000;

				this.serverRequestException = null;
				clientSSLContextFactory = new PKIXSSLContextFactory(
						client1KeyStore, MiniSslClientServer.KEYSTORE_PASSWORD,
						caKeyStore, true);
				sslClientContext = clientSSLContextFactory.buildSSLContext();
				makeClientRequest(sslClientContext);
				result = true;
				if (this.serverRequestException != null) {
					assertTrue(this.serverRequestException instanceof SSLException);
					SSLException sslException = (SSLException) this.serverRequestException;
					Throwable cause = printSslException("! Server: ",
							sslException, null);
					result = (cause == null)
							|| !(cause instanceof CertPathValidatorException);
					if (result == true) {
						throw new RuntimeException(sslException);
					}
				}
				System.out.println();
				assertTrue(result);

				this.serverRequestException = null;
				clientSSLContextFactory = new PKIXSSLContextFactory(
						client2KeyStore, MiniSslClientServer.KEYSTORE_PASSWORD,
						caKeyStore, true);
				sslClientContext = clientSSLContextFactory.buildSSLContext();
				makeClientRequest(sslClientContext);
				result = true;
				if (this.serverRequestException != null) {
					assertTrue(this.serverRequestException instanceof SSLException);
					SSLException sslException = (SSLException) this.serverRequestException;
					Throwable cause = printSslException("! Server: ",
							sslException, null);
					result = (cause == null)
							|| !(cause instanceof CertPathValidatorException);
					if (result == true) {
						throw new RuntimeException(sslException);
					}
				}
				System.out.println();
				assertTrue(result);

				crl = generateCRL(caName, Arrays
						.asList(new BigInteger[] { client2Certificate
								.getSerialNumber() }), caPublicKey,
						caPrivateKey);
				synchronized (PKIXReloadCrlTest.class) {
					PKIXReloadCrlTest.crl = crl;
				}
				Thread.sleep(5000);

				this.serverRequestException = null;
				clientSSLContextFactory = new PKIXSSLContextFactory(
						client1KeyStore, MiniSslClientServer.KEYSTORE_PASSWORD,
						caKeyStore, true);
				sslClientContext = clientSSLContextFactory.buildSSLContext();
				makeClientRequest(sslClientContext);
				result = true;
				if (this.serverRequestException != null) {
					assertTrue(this.serverRequestException instanceof SSLException);
					SSLException sslException = (SSLException) this.serverRequestException;
					Throwable cause = printSslException("! Server: ",
							sslException, null);
					result = (cause == null)
							|| !(cause instanceof CertPathValidatorException);
					if (result == true) {
						throw new RuntimeException(sslException);
					}
				}
				System.out.println();
				assertTrue(result);

				this.serverRequestException = null;
				clientSSLContextFactory = new PKIXSSLContextFactory(
						client2KeyStore, MiniSslClientServer.KEYSTORE_PASSWORD,
						caKeyStore, true);
				sslClientContext = clientSSLContextFactory.buildSSLContext();
				makeClientRequest(sslClientContext);
				result = true;
				if (this.serverRequestException != null) {
					assertTrue(this.serverRequestException instanceof SSLException);
					SSLException sslException = (SSLException) this.serverRequestException;
					Throwable cause = printSslException("! Server: ",
							sslException, null);
					result = (cause == null)
							|| !(cause instanceof CertPathValidatorException);
					if (result == true) {
						throw new RuntimeException(sslException);
					}
				}
				System.out.println();
				assertTrue(!result);
			} finally {
				synchronized (fServerSocket) {
					if (!fServerSocket.isClosed())
						fServerSocket.close();
				}
			}
			synchronized (fServerSocket) {
				assertTrue(fServerSocket.isClosed());
			}
		}
	}
}
