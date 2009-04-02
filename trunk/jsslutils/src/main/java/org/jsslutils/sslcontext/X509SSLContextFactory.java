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

package org.jsslutils.sslcontext;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Properties;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.jsslutils.keystores.KeyStoreLoader;

/**
 * This class is a factory that provides methods for creating an SSLContext
 * configured with the settings set in this factory: using the SunX509 algorithm
 * for both the key manager and the trust manager. These managers are created
 * from the KeyStores passed to the constructor. Unlike the PKIX implementation,
 * this implementation does not support CRLs.
 * 
 * @author Bruno Harbulot
 * 
 */
public class X509SSLContextFactory extends DefaultSSLContextFactory {
	private final static Logger LOGGER = Logger
			.getLogger(X509SSLContextFactory.class.getName());

	public final static String KEYSTORE_FILE_PROP = "org.jsslutils.prop.keyStore";
	public final static String KEYSTORE_TYPE_PROP = "org.jsslutils.prop.keyStoreType";
	public final static String KEYSTORE_PROVIDER_PROP = "org.jsslutils.prop.keyStoreProvider";
	public final static String KEYSTORE_PASSWORD_PROP = "org.jsslutils.prop.keyStorePassword";

	public final static String KEY_PASSWORD_PROP = "org.jsslutils.prop.keyPassword";

	public final static String TRUSTSTORE_FILE_PROP = "org.jsslutils.prop.trustStore";
	public final static String TRUSTSTORE_TYPE_PROP = "org.jsslutils.prop.trustStoreType";
	public final static String TRUSTSTORE_PROVIDER_PROP = "org.jsslutils.prop.trustStoreProvider";
	public final static String TRUSTSTORE_PASSWORD_PROP = "org.jsslutils.prop.trustStorePassword";

	private KeyStore keyStore;
	private char[] keyPassword;
	private KeyStore trustStore;

	private CallbackHandler keyPasswordCallbackHandler;
	private CallbackHandler keyStorePasswordCallbackHandler;
	private CallbackHandler trustStorePasswordCallbackHandler;

	private Class<? extends X509WrappingTrustManager> trustManagerWrapper;

	/**
	 * Builds an SSLContextFactory using the SunX509 algorithm in the
	 * TrustManagerFactory.
	 */
	public X509SSLContextFactory() {
		this(null, (char[]) null, null);
	}

	/**
	 * Builds an SSLContextFactory using the SunX509 algorithm in the
	 * TrustManagerFactory.
	 * 
	 * @param keyStore
	 *            KeyStore that contains the key.
	 * @param keyPassword
	 *            password to the key.
	 * @param trustStore
	 *            KeyStore that contains the trusted X.509 certificates.
	 */
	public X509SSLContextFactory(KeyStore keyStore, String keyPassword,
			KeyStore trustStore) {
		this(keyStore,
				(keyPassword != null) ? keyPassword.toCharArray() : null,
				trustStore);
	}

	/**
	 * Builds an SSLContextFactory using the SunX509 algorithm in the
	 * TrustManagerFactory.
	 * 
	 * @param keyStore
	 *            KeyStore that contains the key.
	 * @param keyPassword
	 *            password to the key.
	 * @param trustStore
	 *            KeyStore that contains the trusted X.509 certificates.
	 */
	public X509SSLContextFactory(KeyStore keyStore, char[] keyPassword,
			KeyStore trustStore) {
		this.keyStore = keyStore;
		this.keyPassword = keyPassword;
		this.trustStore = trustStore;
	}

	@Override
	public void configure(Properties properties)
			throws SSLContextFactoryException {
		super.configure(properties);
		try {
			if (getKeyStore() == null) {
				String keyStorePath = properties
						.getProperty(KEYSTORE_FILE_PROP);
				String keyStoreType = properties
						.getProperty(KEYSTORE_TYPE_PROP);
				String keyStoreProvider = properties
						.getProperty(KEYSTORE_PROVIDER_PROP);
				String keyStorePassword = properties
						.getProperty(KEYSTORE_PASSWORD_PROP);
				if ((keyStorePath != null) || (keyStoreType != null)
						|| (keyStoreProvider != null)
						|| (keyStorePassword != null)) {
					KeyStoreLoader ksl = new KeyStoreLoader();
					ksl.setKeyStorePath(keyStorePath);
					ksl.setKeyStoreType(keyStoreType);
					ksl.setKeyStoreProvider(keyStoreProvider);
					ksl.setKeyStorePassword(keyStorePassword);
					ksl
							.setKeyStorePasswordCallbackHandler(this.keyStorePasswordCallbackHandler);
					this.keyStore = ksl.loadKeyStore();
				}
			}

			if (getTrustStore() == null) {
				String trustStorePath = properties
						.getProperty(TRUSTSTORE_FILE_PROP);
				String trustStoreType = properties
						.getProperty(TRUSTSTORE_TYPE_PROP);
				String trustStoreProvider = properties
						.getProperty(TRUSTSTORE_PROVIDER_PROP);
				String trustStorePassword = properties
						.getProperty(TRUSTSTORE_PASSWORD_PROP);

				if ((trustStorePath != null) || (trustStoreType != null)
						|| (trustStoreProvider != null)
						|| (trustStorePassword != null)) {
					KeyStoreLoader ksl = new KeyStoreLoader();
					ksl.setKeyStorePath(trustStorePath);
					ksl.setKeyStoreType(trustStoreType);
					ksl.setKeyStoreProvider(trustStoreProvider);
					ksl.setKeyStorePassword(trustStorePassword);
					ksl
							.setKeyStorePasswordCallbackHandler(this.trustStorePasswordCallbackHandler);
					this.trustStore = ksl.loadKeyStore();
				}
			}
		} catch (KeyStoreException e) {
			throw new SSLContextFactoryException(e);
		} catch (NoSuchProviderException e) {
			throw new SSLContextFactoryException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new SSLContextFactoryException(e);
		} catch (CertificateException e) {
			throw new SSLContextFactoryException(e);
		} catch (IOException e) {
			throw new SSLContextFactoryException(e);
		} catch (UnsupportedCallbackException e) {
			throw new SSLContextFactoryException(e);
		}
	}

	/**
	 * Sets the key store.
	 * 
	 * @param keyStore
	 *            the key store.
	 */
	public void setKeyStore(KeyStore keyStore) {
		this.keyStore = keyStore;
	}

	/**
	 * Sets the trust store.
	 * 
	 * @param trustStore
	 *            the trust store.
	 */
	public void setTrustStore(KeyStore trustStore) {
		this.trustStore = trustStore;
	}

	/**
	 * Returns the key store.
	 * 
	 * @return the key store.
	 */
	protected KeyStore getKeyStore() {
		return this.keyStore;
	}

	/**
	 * Returns the trust store.
	 * 
	 * @return the trust store.
	 */
	protected KeyStore getTrustStore() {
		return this.trustStore;
	}

	/**
	 * Sets the key password
	 * 
	 * @param keyPassword
	 */
	public void setKeyPassword(char[] keyPassword) {
		this.keyPassword = keyPassword;
	}

	/**
	 * Sets the CallbackHandler that will be used to obtain the key password if
	 * this password is still null. (Optional.)
	 * 
	 * @param keyPasswordCallbackHandler
	 *            CallbackHandler that will be used to get the password.
	 */
	public void setKeyPasswordCallbackHandler(
			CallbackHandler keyPasswordCallbackHandler) {
		this.keyPasswordCallbackHandler = keyPasswordCallbackHandler;
	}

	/**
	 * Sets the CallbackHandler that will be used to obtain the key password if
	 * this password is still null. (Optional.)
	 * 
	 * @param keyStorePasswordCallbackHandler
	 *            CallbackHandler that will be used to get the password.
	 */
	public void setKeyStorePasswordCallbackHandler(
			CallbackHandler keyStorePasswordCallbackHandler) {
		this.keyStorePasswordCallbackHandler = keyStorePasswordCallbackHandler;
	}

	/**
	 * Sets the CallbackHandler that will be used to obtain the key password if
	 * this password is still null. (Optional.)
	 * 
	 * @param trustStorePasswordCallbackHandler
	 *            CallbackHandler that will be used to get the password.
	 */
	public void setTrustStorePasswordCallbackHandler(
			CallbackHandler trustStorePasswordCallbackHandler) {
		this.trustStorePasswordCallbackHandler = trustStorePasswordCallbackHandler;
	}

	/**
	 * Builds KeyManagers from the key store provided in the constructor, using
	 * a SunX509 KeyManagerFactory.
	 * 
	 * @return Key managers corresponding to the key store.
	 */
	@Override
	public KeyManager[] getKeyManagers() throws SSLContextFactoryException {
		if (this.keyStore != null) {
			try {
				KeyManagerFactory kmf = KeyManagerFactory
						.getInstance("SunX509");
				if ((this.keyPassword != null)
						|| (this.keyPasswordCallbackHandler == null)) {
					kmf.init(this.keyStore, this.keyPassword);
				} else {
					PasswordCallback passwordCallback = new PasswordCallback(
							"Key password? ", false);
					this.keyPasswordCallbackHandler
							.handle(new Callback[] { passwordCallback });
					char[] password = passwordCallback.getPassword();
					kmf.init(this.keyStore, password);
					if (password != null) {
						for (int i = 0; i < password.length; i++) {
							password[i] = 0;
						}
					}
				}
				return kmf.getKeyManagers();
			} catch (NoSuchAlgorithmException e) {
				throw new SSLContextFactoryException(e);
			} catch (KeyStoreException e) {
				throw new SSLContextFactoryException(e);
			} catch (UnrecoverableKeyException e) {
				throw new SSLContextFactoryException(e);
			} catch (IOException e) {
				throw new SSLContextFactoryException(e);
			} catch (UnsupportedCallbackException e) {
				throw new SSLContextFactoryException(e);
			}
		} else {
			return null;
		}
	}

	/**
	 * Builds TrustManagers from the trust store provided in the constructor,
	 * using a SunX509 TrustManagerFactory.
	 * 
	 * @return SunX509-based trust managers corresponding to the trust store.
	 */
	protected TrustManager[] getRawTrustManagers()
			throws SSLContextFactoryException {
		if (this.trustStore != null) {
			try {
				TrustManagerFactory tmf = TrustManagerFactory
						.getInstance("SunX509");
				tmf.init(this.trustStore);
				return tmf.getTrustManagers();
			} catch (NoSuchAlgorithmException e) {
				throw new SSLContextFactoryException(e);
			} catch (KeyStoreException e) {
				throw new SSLContextFactoryException(e);
			}
		} else {
			return null;
		}
	}

	/**
	 * Sets the trust manager wrapper.
	 * 
	 * @param trustManagerWrapper
	 */
	public void setTrustManagerWrapper(
			Class<? extends X509WrappingTrustManager> trustManagerWrapper) {
		this.trustManagerWrapper = trustManagerWrapper;
	}

	/**
	 * Gets the trust managers. If a trust manager wrapper has been set, the
	 * "raw" trust managers will be wrapped.
	 * 
	 * @return trust managers.
	 */
	@Override
	public TrustManager[] getTrustManagers() throws SSLContextFactoryException {
		TrustManager[] trustManagers = getRawTrustManagers();
		if (this.trustManagerWrapper != null) {
			try {
				Constructor<? extends X509WrappingTrustManager> constructor = this.trustManagerWrapper
						.getConstructor(X509TrustManager.class);
				for (int i = 0; i < trustManagers.length; i++) {
					trustManagers[i] = constructor
							.newInstance(trustManagers[i]);
				}
			} catch (SecurityException e) {
				LOGGER
						.log(
								Level.WARNING,
								"Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
								e);
			} catch (IllegalArgumentException e) {
				LOGGER
						.log(
								Level.WARNING,
								"Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
								e);
			} catch (NoSuchMethodException e) {
				LOGGER
						.log(
								Level.WARNING,
								"Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
								e);
			} catch (InstantiationException e) {
				LOGGER
						.log(
								Level.WARNING,
								"Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
								e);
			} catch (IllegalAccessException e) {
				LOGGER
						.log(
								Level.WARNING,
								"Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
								e);
			} catch (InvocationTargetException e) {
				LOGGER
						.log(
								Level.WARNING,
								"Error when instantiating the wrapping trust manager. Falling back to unwrapped manager.",
								e);
			}
		}
		return trustManagers;
	}
}
