/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.jsslutils.extra.grizzly;

import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.KeyStore;
import java.util.StringTokenizer;
import java.util.Vector;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;

import org.jsslutils.keystores.KeyStoreLoader;
import org.jsslutils.sslcontext.PKIXSSLContextFactory;
import org.jsslutils.sslcontext.trustmanagers.GsiWrappingTrustManager;
import org.jsslutils.sslcontext.trustmanagers.TrustAllClientsWrappingTrustManager;

import com.sun.grizzly.util.LoggerUtils;
import com.sun.grizzly.util.net.ServerSocketFactory;

/**
 * This socket factory is used by the <a
 * href="http://www.jsslutils.org">jSSLutils</a> SSLImplementation; it is
 * derived from the default JSSESocketFactory provided with Apache Tomcat 6.
 * This is an example for using jSSLutils with Grizzly. It takes the same
 * parameters as the default factory in Grizzly, with the addition of:
 * <ul>
 * <li><i>crlURLs</i>: a space-separated list of URLs of certificate revocation
 * lists.
 * <li><i>acceptProxyCerts</i>: set to 'true' if you wish to use the
 * GsiWrappingTrustManager of jSSLutils (to accept grid proxy certificates).
 * </ul>
 * 
 * @author Harish Prabandham
 * @author Costin Manolache
 * @author Stefan Freyr Stefansson
 * @author EKR -- renamed to JSSESocketFactory
 * @author Jan Luehe
 * @author Bill Barker
 * @author Bruno Harbulot -- jSSLutils
 */
public class JSSLutilsJSSESocketFactory extends ServerSocketFactory {
	private final static Logger logger = LoggerUtils.getLogger();

	public final static String SYSTEM_PROPERTIES_PREFIX = "org.jsslutils.extra.grizzly";

	static String defaultProtocol = "TLS";

	protected volatile boolean initialized;
	protected final String defaultClientAuth = "false";
	protected SSLServerSocketFactory sslProxy = null;
	protected String[] enabledCiphers;

	/**
	 * Flag to state that we require client authentication.
	 */
	protected volatile boolean requireClientAuth = false;

	/**
	 * Flag to state that we would like client authentication.
	 */
	protected volatile boolean wantClientAuth = false;

	public JSSLutilsJSSESocketFactory() {
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(JSSLutilsJSSESocketFactory.class.getName()
					+ " instantiated.");
		}
	}

	@Override
	public ServerSocket createSocket(int port) throws IOException {
		if (!initialized)
			init();
		ServerSocket socket = sslProxy.createServerSocket(port);
		initServerSocket(socket);
		return socket;
	}

	@Override
	public ServerSocket createSocket(int port, int backlog) throws IOException {
		if (!initialized)
			init();
		ServerSocket socket = sslProxy.createServerSocket(port, backlog);
		initServerSocket(socket);
		return socket;
	}

	@Override
	public ServerSocket createSocket(int port, int backlog,
			InetAddress ifAddress) throws IOException {
		if (!initialized)
			init();
		ServerSocket socket = sslProxy.createServerSocket(port, backlog,
				ifAddress);
		initServerSocket(socket);
		return socket;
	}

	@Override
	public Socket acceptSocket(ServerSocket socket) throws IOException {
		SSLSocket asock = null;
		try {
			asock = (SSLSocket) socket.accept();
			configureClientAuth(asock);
			if (logger.isLoggable(Level.FINE)) {
				logger.fine(JSSLutilsJSSESocketFactory.class.getName()
						+ "#acceptSocket(): " + asock.getWantClientAuth() + "/"
						+ asock.getNeedClientAuth());
			}
		} catch (SSLException e) {
			throw new SocketException("SSL handshake error" + e.toString());
		}
		return asock;
	}

	@Override
	public void handshake(Socket sock) throws IOException {
		((SSLSocket) sock).startHandshake();
	}

	/**
	 * Determines the SSL cipher suites to be enabled.
	 * 
	 * @param requestedCiphers
	 *            Comma-separated list of requested ciphers @param
	 *            supportedCiphers Array of supported ciphers
	 * 
	 * @return Array of SSL cipher suites to be enabled, or null if none of the
	 *         requested ciphers are supported
	 */
	protected synchronized String[] getEnabledCiphers(String requestedCiphers,
			String[] supportedCiphers) {

		String[] enabledCiphers = null;

		if (requestedCiphers != null) {
			Vector<String> vec = null;
			String cipher = requestedCiphers;
			int index = requestedCiphers.indexOf(',');
			if (index != -1) {
				int fromIndex = 0;
				while (index != -1) {
					cipher = requestedCiphers.substring(fromIndex, index)
							.trim();
					if (cipher.length() > 0) {
						/*
						 * Check to see if the requested cipher is among the
						 * supported ciphers, i.e., may be enabled
						 */
						for (int i = 0; supportedCiphers != null
								&& i < supportedCiphers.length; i++) {
							if (supportedCiphers[i].equals(cipher)) {
								if (vec == null) {
									vec = new Vector<String>();
								}
								vec.addElement(cipher);
								break;
							}
						}
					}
					fromIndex = index + 1;
					index = requestedCiphers.indexOf(',', fromIndex);
				} // while
				cipher = requestedCiphers.substring(fromIndex);
			}

			if (cipher != null) {
				cipher = cipher.trim();
				if (cipher.length() > 0) {
					/*
					 * Check to see if the requested cipher is among the
					 * supported ciphers, i.e., may be enabled
					 */
					for (int i = 0; supportedCiphers != null
							&& i < supportedCiphers.length; i++) {
						if (supportedCiphers[i].equals(cipher)) {
							if (vec == null) {
								vec = new Vector<String>();
							}
							vec.addElement(cipher);
							break;
						}
					}
				}
			}

			if (vec != null) {
				enabledCiphers = new String[vec.size()];
				vec.copyInto(enabledCiphers);
			}
		} else {
			enabledCiphers = sslProxy.getDefaultCipherSuites();
		}

		return enabledCiphers;
	}

	/**
	 * Reads the keystore and initializes the SSL socket factory.
	 */
	@Override
	public void init() throws IOException {
		try {
			String clientAuthStr = System.getProperty(SYSTEM_PROPERTIES_PREFIX
					+ ".clientauth", (String) attributes.get("clientauth"));
			if ("true".equalsIgnoreCase(clientAuthStr)
					|| "yes".equalsIgnoreCase(clientAuthStr)) {
				requireClientAuth = true;
			} else if ("want".equalsIgnoreCase(clientAuthStr)) {
				wantClientAuth = true;
			}

			// SSL protocol variant (e.g., TLS, SSL v3, etc.)
			String protocol = System.getProperty(SYSTEM_PROPERTIES_PREFIX
					+ ".protocol", (String) attributes.get("protocol"));
			if (protocol == null) {
				protocol = defaultProtocol;
			}

			String keyPassAttr = System.getProperty(SYSTEM_PROPERTIES_PREFIX
					+ ".keypass", (String) attributes.get("keypass"));

			KeyStoreLoader ksl = KeyStoreLoader.getKeyStoreDefaultLoader();
			String keystoreFileAttr = System.getProperty(
					SYSTEM_PROPERTIES_PREFIX + ".keystore", (String) attributes
							.get("keystoreFile"));
			if (keystoreFileAttr == null) {
				keystoreFileAttr = (String) attributes.get("keystore");
			}
			if (keystoreFileAttr != null) {
				ksl.setKeyStorePath(keystoreFileAttr.length() == 0 ? null
						: keystoreFileAttr);
			}
			String keystorePassAttr = System.getProperty(
					SYSTEM_PROPERTIES_PREFIX + ".keystorePass",
					(String) attributes.get("keystorePass"));
			if (keystorePassAttr == null) {
				keystorePassAttr = keyPassAttr;
			}
			if (keystorePassAttr != null)
				ksl.setKeyStorePassword(keystorePassAttr);
			String keystoreTypeAttr = System.getProperty(
					SYSTEM_PROPERTIES_PREFIX + ".keystoreType",
					(String) attributes.get("keystoreType"));
			ksl.setKeyStoreType(keystoreTypeAttr != null ? keystoreTypeAttr
					: KeyStore.getDefaultType());
			String keystoreProviderAttr = System.getProperty(
					SYSTEM_PROPERTIES_PREFIX + ".keystoreProvider",
					(String) attributes.get("keystoreProvider"));
			if (keystoreProviderAttr != null) {
				ksl
						.setKeyStoreProvider(keystoreProviderAttr.length() == 0 ? null
								: keystoreProviderAttr);
			}

			KeyStoreLoader tsl = KeyStoreLoader.getTrustStoreDefaultLoader();
			String truststoreFileAttr = System.getProperty(
					SYSTEM_PROPERTIES_PREFIX + ".truststoreFile",
					(String) attributes.get("truststoreFile"));
			if (truststoreFileAttr != null) {
				tsl.setKeyStorePath(truststoreFileAttr.length() == 0 ? null
						: truststoreFileAttr);
			}
			String truststorePassAttr = System.getProperty(
					SYSTEM_PROPERTIES_PREFIX + ".truststorePass",
					(String) attributes.get("truststorePass"));
			if (truststorePassAttr != null)
				tsl.setKeyStorePassword(truststorePassAttr);
			String truststoreTypeAttr = System.getProperty(
					SYSTEM_PROPERTIES_PREFIX + ".truststoreType",
					(String) attributes.get("truststoreType"));
			tsl.setKeyStoreType(truststoreTypeAttr != null ? truststoreTypeAttr
					: KeyStore.getDefaultType());
			String truststoreProviderAttr = System.getProperty(
					SYSTEM_PROPERTIES_PREFIX + ".truststoreProvider",
					(String) attributes.get("truststoreProvider"));
			if (truststoreProviderAttr != null) {
				tsl
						.setKeyStoreProvider(truststoreProviderAttr.length() == 0 ? null
								: truststoreProviderAttr);
			}

			KeyStore keyStore = ksl.loadKeyStore();
			KeyStore trustStore = tsl.loadKeyStore();

			PKIXSSLContextFactory sslContextFactory = new PKIXSSLContextFactory(
					keyStore, keyPassAttr, trustStore);

			String crlURLsAttr = System.getProperty(SYSTEM_PROPERTIES_PREFIX
					+ ".crlURLs", (String) attributes.get("crlURLs"));
			if (crlURLsAttr != null) {
				StringTokenizer st = new StringTokenizer(crlURLsAttr, " ");
				while (st.hasMoreTokens()) {
					String crlUrl = st.nextToken();
					sslContextFactory.addCrl(crlUrl);
				}
			}

			String acceptAnyCert = System.getProperty(SYSTEM_PROPERTIES_PREFIX
					+ ".acceptAnyCert", (String) attributes
					.get("acceptAnyCert"));
			if ("true".equalsIgnoreCase(acceptAnyCert)
					|| "yes".equalsIgnoreCase(acceptAnyCert)) {
				sslContextFactory
						.setTrustManagerWrapper(new TrustAllClientsWrappingTrustManager.Wrapper());
			} else {
				String acceptProxyCertsAttr = System.getProperty(
						SYSTEM_PROPERTIES_PREFIX + ".acceptProxyCerts",
						(String) attributes.get("acceptProxyCerts"));
				if ("true".equalsIgnoreCase(acceptProxyCertsAttr)
						|| "yes".equalsIgnoreCase(acceptProxyCertsAttr)) {
					sslContextFactory
							.setTrustManagerWrapper(new GsiWrappingTrustManager.Wrapper());
				}
			}

			// Create and init SSLContext
			SSLContext context = sslContextFactory.buildSSLContext(protocol);

			// create proxy
			sslProxy = context.getServerSocketFactory();

			// Determine which cipher suites to enable
			String requestedCiphers = System.getProperty(
					SYSTEM_PROPERTIES_PREFIX + ".ciphers", (String) attributes
							.get("ciphers"));

			synchronized (this) {
				enabledCiphers = getEnabledCiphers(requestedCiphers, sslProxy
						.getSupportedCipherSuites());
			}
		} catch (Exception e) {
			if (e instanceof IOException)
				throw (IOException) e;
			throw new IOException(e.getMessage());
		}
	}

	/**
	 * Set the SSL protocol variants to be enabled.
	 * 
	 * @param socket
	 *            the SSLServerSocket.
	 * @param protocols
	 *            the protocols to use.
	 */
	protected void setEnabledProtocols(SSLServerSocket socket,
			String[] protocols) {
		if (protocols != null) {
			socket.setEnabledProtocols(protocols);
		}
	}

	/**
	 * Determines the SSL protocol variants to be enabled.
	 * 
	 * @param socket
	 *            The socket to get supported list from.
	 * @param requestedProtocols
	 *            Comma-separated list of requested SSL protocol variants
	 * 
	 * @return Array of SSL protocol variants to be enabled, or null if none of
	 *         the requested protocol variants are supported
	 */
	protected String[] getEnabledProtocols(SSLServerSocket socket,
			String requestedProtocols) {
		String[] supportedProtocols = socket.getSupportedProtocols();

		String[] enabledProtocols = null;

		if (requestedProtocols != null) {
			Vector<String> vec = null;
			String protocol = requestedProtocols;
			int index = requestedProtocols.indexOf(',');
			if (index != -1) {
				int fromIndex = 0;
				while (index != -1) {
					protocol = requestedProtocols.substring(fromIndex, index)
							.trim();
					if (protocol.length() > 0) {
						/*
						 * Check to see if the requested protocol is among the
						 * supported protocols, i.e., may be enabled
						 */
						for (int i = 0; supportedProtocols != null
								&& i < supportedProtocols.length; i++) {
							if (supportedProtocols[i].equals(protocol)) {
								if (vec == null) {
									vec = new Vector<String>();
								}
								vec.addElement(protocol);
								break;
							}
						}
					}
					fromIndex = index + 1;
					index = requestedProtocols.indexOf(',', fromIndex);
				} // while
				protocol = requestedProtocols.substring(fromIndex);
			}

			if (protocol != null) {
				protocol = protocol.trim();
				if (protocol.length() > 0) {
					/*
					 * Check to see if the requested protocol is among the
					 * supported protocols, i.e., may be enabled
					 */
					for (int i = 0; supportedProtocols != null
							&& i < supportedProtocols.length; i++) {
						if (supportedProtocols[i].equals(protocol)) {
							if (vec == null) {
								vec = new Vector<String>();
							}
							vec.addElement(protocol);
							break;
						}
					}
				}
			}

			if (vec != null) {
				enabledProtocols = new String[vec.size()];
				vec.copyInto(enabledProtocols);
			}
		}

		return enabledProtocols;
	}

	/**
	 * Configure Client authentication for this version of JSSE. The JSSE
	 * included in Java 1.4 supports the 'want' value. Prior versions of JSSE
	 * will treat 'want' as 'false'.
	 * 
	 * @param socket
	 *            the SSLServerSocket
	 */
	protected void configureClientAuth(SSLServerSocket socket) {

		if (wantClientAuth) {
			socket.setWantClientAuth(wantClientAuth);
		} else {
			socket.setNeedClientAuth(requireClientAuth);
		}
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(JSSLutilsJSSESocketFactory.class.getName()
					+ "#configureClientAuth(): " + socket.getWantClientAuth()
					+ "/" + socket.getNeedClientAuth());
		}
	}

	/**
	 * Configure Client authentication for this version of JSSE. The JSSE
	 * included in Java 1.4 supports the 'want' value. Prior versions of JSSE
	 * will treat 'want' as 'false'.
	 * 
	 * @param socket
	 *            the SSLSocket
	 */
	protected void configureClientAuth(SSLSocket socket) {

		if (wantClientAuth) {
			socket.setWantClientAuth(wantClientAuth);
		} else {
			socket.setNeedClientAuth(requireClientAuth);
		}
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(JSSLutilsJSSESocketFactory.class.getName()
					+ "#configureClientAuth(): " + socket.getWantClientAuth()
					+ "/" + socket.getNeedClientAuth());
		}
	}

	/**
	 * Configures the given SSL server socket with the requested cipher suites,
	 * protocol versions, and need for client authentication
	 */
	private void initServerSocket(ServerSocket ssocket) {
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(JSSLutilsJSSESocketFactory.class.getName()
					+ "#initServerSocket(): ");
		}
		SSLServerSocket socket = (SSLServerSocket) ssocket;

		synchronized (this) {
			if (enabledCiphers != null) {
				socket.setEnabledCipherSuites(enabledCiphers);
			}
		}

		String requestedProtocols = (String) attributes.get("protocols");
		setEnabledProtocols(socket, getEnabledProtocols(socket,
				requestedProtocols));

		// we don't know if client auth is needed -
		// after parsing the request we may re-handshake
		configureClientAuth(socket);
	}

}
