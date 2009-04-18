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

import static org.junit.Assert.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidatorException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * This class contains both a client and a server that can be used to build
 * small tests, to test the SSLContextFactory.
 * 
 * These examples come with a demo CA (a few certificates and keys). These are
 * not to be used in real-life application. DO NOT add them to your set of
 * trusted certificates in your web-browser or similar application.
 * 
 * @author Bruno Harbulot.
 * 
 */
public abstract class MiniSslClientServer {
	protected boolean verboseExceptions = false;
	protected int serverTimeout = 4000;
	protected int testPort = 31050;

	public final static String CERTIFICATES_DIRECTORY = "org/jsslutils/certificates/";
	public final static char[] KEYSTORE_PASSWORD = "testtest".toCharArray();

	protected String getCertificatesDirectory() {
		return CERTIFICATES_DIRECTORY + "local/";
	}

	/**
	 * Returns the store of CA certificates, to be used as a trust store. The
	 * default value is to load 'dummy.jks', part of this test suite.
	 * 
	 * @return KeyStore containing the certificates to trust.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 */
	public KeyStore getCaKeyStore() throws IOException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException {
		KeyStore ks = KeyStore.getInstance("JKS");
		InputStream ksis = ClassLoader
				.getSystemResourceAsStream(getCertificatesDirectory()
						+ "cacert.jks");
		ks.load(ksis, KEYSTORE_PASSWORD);
		ksis.close();
		return ks;
	}

	/**
	 * Returns the keystore containing the key and the certificate to be used by
	 * the server.
	 * 
	 * @return KeyStore containing the server credentials.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 */
	public KeyStore getServerCertKeyStore() throws IOException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		InputStream ksis = ClassLoader
				.getSystemResourceAsStream(getCertificatesDirectory()
						+ "localhost.p12");
		ks.load(ksis, KEYSTORE_PASSWORD);
		ksis.close();
		return ks;
	}

	/**
	 * Returns the keystore containing a test key and certificate that is to be
	 * trusted by the server. This is the "good" keystore in that its
	 * certificate has not been revoked by the demo CA. This should work
	 * whether-or-not CRLs are used.
	 * 
	 * @return KeyStore containing the "good" client credentials.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 */
	public KeyStore getGoodClientCertKeyStore() throws IOException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		InputStream ksis = ClassLoader
				.getSystemResourceAsStream(getCertificatesDirectory()
						+ "testclient.p12");
		ks.load(ksis, KEYSTORE_PASSWORD);
		ksis.close();
		return ks;
	}

	/**
	 * Returns the keystore containing a test key and certificate that is not to
	 * be trusted by the server when CRLs are enabled. This is the "bad"
	 * keystore in that its certificate has been revoked by the demo CA. This
	 * should pass work when CRLs checks are disabled, but fail when they are
	 * used.
	 * 
	 * @return KeyStore containing the "bad" client credentials.
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 */
	public KeyStore getBadClientCertKeyStore() throws IOException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException {
		KeyStore ks = KeyStore.getInstance("PKCS12");
		InputStream ksis = ClassLoader
				.getSystemResourceAsStream(getCertificatesDirectory()
						+ "testclient_r.p12");
		ks.load(ksis, KEYSTORE_PASSWORD);
		ksis.close();
		return ks;
	}

	/**
	 * Returns a collection of CRLs to be used by the tests. This is loaded from
	 * 'newca.crl'.
	 * 
	 * @return CRLs
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws KeyStoreException
	 * @throws CertificateException
	 * @throws CRLException
	 */
	public Collection<X509CRL> getLocalCRLs() throws IOException,
			NoSuchAlgorithmException, KeyStoreException, CertificateException,
			CRLException {
		InputStream inStream = ClassLoader
				.getSystemResourceAsStream(getCertificatesDirectory()
						+ "testca-crl.pem");
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509CRL crl = (X509CRL) cf.generateCRL(inStream);
		inStream.close();
		ArrayList<X509CRL> crls = new ArrayList<X509CRL>();
		crls.add(crl);
		return crls;
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
			SSLContext sslServerContext) throws IOException {
		this.requestException = null;
		boolean result = false;

		SSLServerSocket serverSocket = prepareServerSocket(sslServerContext);

		assertNotNull("Server socket not null", serverSocket);
		assertTrue("Server socket is bound", serverSocket.isBound());

		final SSLServerSocket fServerSocket = serverSocket;
		if (fServerSocket != null) {
			runServer(fServerSocket);

			try {
				doClientRequest(sslClientContext);
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
		result = true;
		if (this.requestException != null) {
			assertTrue(this.requestException instanceof SSLException);
			SSLException sslException = (SSLException) this.requestException;
			Throwable cause = printSslException("! Server: ", sslException,
					null);
			result = (cause == null)
					|| !(cause instanceof CertPathValidatorException);
			if (result == true) {
				throw new RuntimeException(sslException);
			}
		}
		System.out.println();

		return result;
	}

	/**
	 * @param sslClientSocketFactory
	 * @throws IOException
	 */
	protected void doClientRequest(SSLContext sslClientContext)
			throws IOException {
		SSLSocketFactory sslClientSocketFactory = sslClientContext
				.getSocketFactory();

		PrintWriter cout = null;
		BufferedReader cin = null;
		SSLSocket sslClientSocket = null;
		try {
			sslClientSocket = (SSLSocket) sslClientSocketFactory.createSocket(
					"localhost", testPort);
			assertTrue("Client socket connected", sslClientSocket.isConnected());

			sslClientSocket.setSoTimeout(500);
			cin = new BufferedReader(new InputStreamReader(sslClientSocket
					.getInputStream()));
			String inputLine = null;

			cout = new PrintWriter(sslClientSocket.getOutputStream(), true);
			cout.println("GET / HTTP/1.1");
			cout.println("Host: localhost");
			cout.println();
			while ((inputLine = cin.readLine()) != null) {
				System.out.println("Server says: " + inputLine);
			}
		} catch (SSLException e) {
			printSslException("! Client: ", e, sslClientSocket);
		} catch (IOException e) {
			e.printStackTrace();
			fail();
		} finally {
			if (cin != null)
				cin.close();
			if (cout != null)
				cout.close();
		}
	}

	/**
	 * Sets the number of requests the mini server is supposed to accept. This
	 * defaults to 1, with a 4-second timeout.
	 * 
	 * @param serverRequestNumber
	 */
	protected void setServerRequestNumber(int serverRequestNumber) {
		this.serverRequestNumber = serverRequestNumber;
	}

	private int serverRequestNumber = 1;

	/**
	 * Starts the mini server.
	 * 
	 * @param fServerSocket
	 *            bound SSLServerSocket for this server.
	 */
	protected void runServer(final SSLServerSocket fServerSocket) {
		final ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(2,
				10, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<Runnable>());
		Thread serverThread = new Thread(new Runnable() {
			public void run() {
				int max = MiniSslClientServer.this.serverRequestNumber;
				for (int i = max; i > 0 || max == 0; i--) {
					Socket acceptedSocket = null;
					try {
						fServerSocket.setSoTimeout(serverTimeout);
						acceptedSocket = fServerSocket.accept();
						threadPoolExecutor.execute(new RequestHandler(
								acceptedSocket));
					} catch (IOException e) {
						MiniSslClientServer.this.requestException = e;
					}
				}
				try {
					synchronized (fServerSocket) {
						if (!fServerSocket.isClosed())
							fServerSocket.close();
					}
				} catch (IOException e) {
					MiniSslClientServer.this.requestException = e;
				}
			}
		});
		serverThread.start();
	}

	/**
	 * Creates and binds the SSLServerSocket to a port after trying a few port
	 * numbers.
	 * 
	 * @param sslServerContext
	 *            SSLContext from which to build the socket and its
	 *            SSLSocketFactory.
	 * @return Bound SSLServerSocket.
	 */
	protected SSLServerSocket prepareServerSocket(SSLContext sslServerContext) {
		SSLServerSocketFactory sslServerSocketFactory = sslServerContext
				.getServerSocketFactory();

		SSLServerSocket serverSocket = null;
		int attempts = 10;
		while (attempts > 0) {

			try {
				serverSocket = (SSLServerSocket) sslServerSocketFactory
						.createServerSocket(++testPort);
				serverSocket.setWantClientAuth(true);
				System.out.println("Server listening at: https://localhost:"
						+ testPort + "/");
				break;
			} catch (IOException e) {
				System.err.println("Could not listen on port: " + testPort);
			}
			serverSocket = null;
			attempts--;
		}
		return serverSocket;
	}

	protected Exception requestException;

	/**
	 * Small class that handles a server request.
	 */
	protected class RequestHandler implements Runnable {
		private final Socket clientSocket;

		public RequestHandler(Socket clientSocket) {
			this.clientSocket = clientSocket;
		}

		public void run() {
			System.out.println("Accepted connection.");
			try {
				PrintWriter out = new PrintWriter(clientSocket
						.getOutputStream(), true);
				BufferedReader in = new BufferedReader(new InputStreamReader(
						clientSocket.getInputStream()));
				String inputLine;

				while ((inputLine = in.readLine()) != null) {
					System.out.println("Client says: " + inputLine);
					if (inputLine.length() == 0)
						break;
				}

				String theOutput = "HTTP/1.0 200 OK\r\n";
				theOutput += "Content-type: text/plain\r\n";
				theOutput += "\r\n";
				theOutput += "Hello World\r\n";
				if (this.clientSocket instanceof SSLSocket) {
					SSLSocket sslSocket = (SSLSocket) this.clientSocket;
					SSLSession sslSession = sslSocket.getSession();
					if (sslSession != null) {
						System.out.println("Cipher suite: "
								+ sslSession.getCipherSuite());
						theOutput += "Cipher suite: "
								+ sslSession.getCipherSuite() + "\r\n";
						theOutput += "Client certificates: \r\n";

						X509Certificate[] certs = null;
						try {
							certs = (X509Certificate[]) sslSession
									.getPeerCertificates();
						} catch (SSLPeerUnverifiedException e) {
						}
						if (certs != null) {
							for (X509Certificate cert : certs) {
								theOutput += " - "
										+ cert.getSubjectX500Principal()
												.getName() + "\r\n";
							}
						}
					}
				}
				out.print(theOutput);

				out.close();
				in.close();
			} catch (Exception e) {
				if (MiniSslClientServer.this.verboseExceptions) {
					e.printStackTrace();
				}
				MiniSslClientServer.this.requestException = e;
			} finally {
				try {
					clientSocket.close();
				} catch (IOException e) {
					if (MiniSslClientServer.this.verboseExceptions) {
						e.printStackTrace();
					}
					throw new RuntimeException(e);
				}
			}
		}
	}

	/**
	 * Used for printing out more info when there's a problem.
	 * 
	 * @param prefix
	 * @param sslException
	 * @param socket
	 * @return
	 */
	private Throwable printSslException(String prefix,
			SSLException sslException, SSLSocket socket) {
		Throwable cause = sslException;
		while ((cause = cause.getCause()) != null) {
			if (cause instanceof CertPathValidatorException) {
				CertPathValidatorException certException = (CertPathValidatorException) cause;
				CertPath certPath = certException.getCertPath();
				List<? extends Certificate> certificates = certPath
						.getCertificates();
				int index = certException.getIndex();
				if (index >= 0) {
					Certificate pbCertificate = certificates.get(index);
					if (pbCertificate instanceof X509Certificate) {
						System.out.println(prefix
								+ "Problem caused by cert: "
								+ ((X509Certificate) pbCertificate)
										.getSubjectX500Principal().getName());
					} else {
						System.out.println(prefix + "Problem caused by cert: "
								+ pbCertificate);
					}
				} else {
					System.out.println(prefix + "Unknown index: " + cause);
				}
				break;
			} else {
				System.out.println(prefix + cause);
				if (socket != null) {
					printSslSocketInfo(socket);
				}
			}
		}
		return cause;
	}

	/**
	 * Used for printing out more info when there's a problem.
	 * 
	 * @param socket
	 */
	private void printSslSocketInfo(SSLSocket socket) {
		System.out.println("Socket: " + socket);
		SSLSession session = socket.getSession();
		if (session != null) {
			System.out.println("Session: " + session);
			System.out.println("  Local certificates: "
					+ session.getLocalCertificates());
			System.out.println("  Local principal: "
					+ session.getLocalPrincipal());
			SSLSessionContext context = session.getSessionContext();
			if (context != null) {
				System.out.println("Session context: " + context);
			}
		}
	}

}
