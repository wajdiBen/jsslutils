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
package org.jsslutils.keystores;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

/**
 * This class is a factory that provides methods for loading a KeyStore.
 * 
 * @author Bruno Harbulot
 * 
 */
public final class KeyStoreLoader {
	private volatile String keyStorePath;
	private volatile String keyStoreType;
	private volatile String keyStoreProvider;
	private volatile char[] keyStorePassword;

	/**
	 * Sets the KeyStore path.
	 * 
	 * @param keyStorePath
	 *            the KeyStore path
	 */
	public void setKeyStorePath(String keyStorePath) {
		this.keyStorePath = keyStorePath;
	}

	/**
	 * Sets the KeyStore type.
	 * 
	 * @param keyStoreType
	 *            the KeyStore type
	 */
	public void setKeyStoreType(String keyStoreType) {
		this.keyStoreType = keyStoreType;
	}

	/**
	 * Sets the KeyStore provider.
	 * 
	 * @param keyStoreProvider
	 *            the KeyStore provider
	 */
	public void setKeyStoreProvider(String keyStoreProvider) {
		this.keyStoreProvider = keyStoreProvider;
	}

	/**
	 * Set the KeyStore password.
	 * 
	 * @param keyStorePassword
	 *            the KeyStore password
	 */
	public void setKeyStorePassword(String keyStorePassword) {
		setKeyStorePassword((keyStorePassword != null) ? keyStorePassword
				.toCharArray() : null);
	}

	/**
	 * Set the KeyStore password.
	 * 
	 * @param keyStorePassword
	 *            the KeyStore password
	 */
	public void setKeyStorePassword(char[] keyStorePassword) {
		this.keyStorePassword = keyStorePassword;
	}

	/**
	 * Loads a KeyStore according to the parameters initialised using the
	 * setters.
	 * 
	 * @param password
	 *            KeyStore password (will use password set with
	 *            setKeyStorePassword if this argument is null).
	 * @return KeyStore loaded from the value initialised with the setters.
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	public KeyStore loadKeyStore(char[] password) throws KeyStoreException,
			NoSuchProviderException, IOException, NoSuchAlgorithmException,
			CertificateException {
		KeyStore keyStore;
		if (this.keyStoreProvider != null) {
			keyStore = KeyStore.getInstance(
					this.keyStoreType != null ? this.keyStoreType : KeyStore
							.getDefaultType(), this.keyStoreProvider);
		} else {
			keyStore = KeyStore
					.getInstance(this.keyStoreType != null ? this.keyStoreType
							: KeyStore.getDefaultType());
		}
		FileInputStream keyStoreInputStream = null;
		try {
			keyStoreInputStream = ((this.keyStorePath != null) && (!"NONE"
					.equals(this.keyStorePath))) ? new FileInputStream(
					this.keyStorePath) : null;
			keyStore.load(keyStoreInputStream, (password != null) ? password
					: this.keyStorePassword);
		} finally {
			if (keyStoreInputStream != null) {
				keyStoreInputStream.close();
			}
		}
		return keyStore;
	}

	/**
	 * Loads a KeyStore according to the parameters initialised using the
	 * setters.
	 * 
	 * @return KeyStore loaded from the value initialised with the setters.
	 * @throws KeyStoreException
	 * @throws NoSuchProviderException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws CertificateException
	 */
	public KeyStore loadKeyStore() throws KeyStoreException,
			NoSuchProviderException, IOException, NoSuchAlgorithmException,
			CertificateException {
		return loadKeyStore(null);
	}

	/**
	 * Builds a new KeyStoreLoader initialised with the values passed in the
	 * javax.net.ssl.keyStore, javax.net.ssl.keyStoreType,
	 * javax.net.ssl.keyStoreProvider and javax.net.ssl.keyStorePassword system
	 * properties, for using the KeyStore as a key store (as opposed to a trust
	 * store).
	 * 
	 * @return KeyStore initialised with the default keystore system properties.
	 */
	public static KeyStoreLoader getKeyStoreDefaultLoader() {
		KeyStoreLoader ksLoader = new KeyStoreLoader();
		ksLoader.setKeyStorePath(System.getProperty("javax.net.ssl.keyStore"));
		ksLoader.setKeyStoreType(System
				.getProperty("javax.net.ssl.keyStoreType"));
		ksLoader.setKeyStoreProvider(System
				.getProperty("javax.net.ssl.keyStoreProvider"));
		ksLoader.setKeyStorePassword(System
				.getProperty("javax.net.ssl.keyStorePassword"));
		return ksLoader;
	}

	/**
	 * Builds a new KeyStoreLoader initialised with the values passed in the
	 * javax.net.ssl.trustStore, javax.net.ssl.trustStoreType,
	 * javax.net.ssl.trustStoreProvider and javax.net.ssl.trustStorePassword
	 * system properties, for using the KeyStore as a trust store.
	 * 
	 * @return KeyStore initialised with the default keystore system properties.
	 */
	public static KeyStoreLoader getTrustStoreDefaultLoader() {
		KeyStoreLoader ksLoader = new KeyStoreLoader();
		ksLoader
				.setKeyStorePath(System.getProperty("javax.net.ssl.trustStore"));
		ksLoader.setKeyStoreType(System
				.getProperty("javax.net.ssl.trustStoreType"));
		ksLoader.setKeyStoreProvider(System
				.getProperty("javax.net.ssl.trustStoreProvider"));
		ksLoader.setKeyStorePassword(System
				.getProperty("javax.net.ssl.trustStorePassword"));
		return ksLoader;
	}

	/**
	 * KeyStoreLoaders are likely to contain sensitive information; cloning is
	 * therefore not allowed.
	 */
	protected final KeyStoreLoader clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException();
	}
}
