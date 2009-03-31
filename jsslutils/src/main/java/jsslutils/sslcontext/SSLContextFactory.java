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

import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 * This class is a factory that provides methods for creating an SSLContext
 * configured with the settings set in this factory. It creates and initialises
 * the SSLContext with init(getKeyManagers(), getTrustManagers(),
 * getSecureRandom()), which all default to null. These three methods can be
 * overridden.
 * 
 * @author Bruno Harbulot
 * 
 */
public class SSLContextFactory {
	private String contextProtocol = "SSLv3";
	private Provider contextProvider = null;
	private Provider defaultSecureRandomProvider = null;
	private String defaultSecureRandomAlgorithm = null;
	private SecureRandom secureRandom = null;

	/**
	 * Sets the Provider used for creating the SSLContext (defaults to null).
	 * 
	 * @param contextProvider
	 *            Provider used to create the SSLContext.
	 */
	public void setContextProvider(Provider contextProvider) {
		this.contextProvider = contextProvider;
	}

	/**
	 * Sets the Provider used for creating the SSLContext (defaults to null),
	 * using Security.getProvider(contextProviderName).
	 * 
	 * @param contextProviderName
	 *            name of the Provider to use.
	 */
	public void setContextProvider(String contextProviderName)
			throws SSLContextFactoryException {
		if (contextProviderName != null) {
			this.contextProvider = Security.getProvider(contextProviderName);
			if (this.contextProvider == null) {
				throw new SSLContextFactoryException(
						new NoSuchProviderException(contextProviderName));
			}
		} else {
			this.contextProvider = null;
		}
	}

	/**
	 * Returns the Provider that is used for creating the SSLContext.
	 * 
	 * @return Provider that is used for creating the SSLContext.
	 */
	public Provider getContextProvider() {
		return this.contextProvider;
	}

	/**
	 * Sets the name of the Provider used for creating the SSLContext (defaults
	 * to null). It is only used if there is no Provider set using
	 * setContextProvider(Provider).
	 * 
	 * @param contextProviderName
	 *            name of the Provider to use.
	 */
	@Deprecated
	public void setContextProviderName(String contextProviderName) {
		try {
			setContextProvider(contextProviderName);
		} catch (SSLContextFactoryException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Returns the name of the provider that is used for creating the
	 * SSLContext, if one is set. If there is an actual provider set,
	 * Provider.getName() is used, otherwise, it returns the context provider
	 * name, set as a String.
	 * 
	 * @return Name of the context Provider.
	 */
	@Deprecated
	public String getContextProviderName() {
		return (this.contextProvider != null) ? this.contextProvider.getName()
				: null;
	}

	/**
	 * Sets the protocol to be used for creating a new SSLContext. If no value
	 * is set, this defaults to "SSLv3".
	 * 
	 * @param contextProtocol
	 *            protocol to be used to create the SSLContext.
	 */
	public void setContextProtocol(String contextProtocol) {
		this.contextProtocol = contextProtocol;
	}

	/**
	 * Returns the protocol to be used for creating a new SSLContext.
	 * 
	 * @return Protocol to be used to create the SSLContext.
	 */
	public String getContextProtocol() {
		return this.contextProtocol;
	}

	/**
	 * Returns the default SecureRandom Provider.
	 * 
	 * @return The default SecureRandom Provider.
	 */
	public Provider getDefaultSecureRandomProvider() {
		return this.defaultSecureRandomProvider;
	}

	/**
	 * Sets the default SecureRandom Provider.
	 * 
	 * @param secureRandomProvider
	 *            the default SecureRandom Provider to set
	 */
	public void setDefaultSecureRandomProvider(Provider secureRandomProvider) {
		this.defaultSecureRandomProvider = secureRandomProvider;
	}

	/**
	 * Sets the default SecureRandom Provider, by name.
	 * 
	 * @param secureRandomProviderName
	 *            the default SecureRandom Provider to set
	 */
	public void setDefaultSecureRandomProvider(String secureRandomProviderName) {
		this.defaultSecureRandomProvider = Security
				.getProvider(secureRandomProviderName);
	}

	/**
	 * Returns the default SecureRandom algorithm.
	 * 
	 * @return The default SecureRandom algorithm.
	 */
	public String getDefaultSecureRandomAlgorithm() {
		return this.defaultSecureRandomAlgorithm;
	}

	/**
	 * Sets the default SecureRandom algorithm.
	 * 
	 * @param secureRandomAlgorithm
	 *            the default SecureRandom algorithm to set
	 */
	public void setDefaultSecureRandomAlgorithm(String secureRandomAlgorithm) {
		this.defaultSecureRandomAlgorithm = secureRandomAlgorithm;
	}

	/**
	 * @see SSLContextFactory#buildSSLContext()
	 */
	@Deprecated
	public SSLContext newInitializedSSLContext()
			throws SSLContextFactoryException {
		return buildSSLContext(contextProtocol);
	}

	/**
	 * @see SSLContextFactory#buildSSLContext(String)
	 */
	@Deprecated
	public SSLContext newInitializedSSLContext(String contextProtocol)
			throws SSLContextFactoryException {
		return buildSSLContext(contextProtocol);
	}

	/**
	 * Creates a new SSLContext with the context protocol set with
	 * setContextProtocol(String). The default value is "SSLv3".
	 * 
	 * @return SSLContext initialised with getKeyManagers(), getTrustManagers()
	 *         and getSecureRandom().
	 * @throws SSLContextFactoryException
	 */
	public SSLContext buildSSLContext() throws SSLContextFactoryException {
		return buildSSLContext(contextProtocol);
	}

	/**
	 * Creates a new SSLContext initialised with getKeyManagers(),
	 * getTrustManagers() and getSecureRandom(). The provider is that set up
	 * with setContextProvider() or setContextProviderName().
	 * 
	 * @param contextProtocol
	 *            SSLContext protocol.
	 * @return SSLContext initialised with getKeyManagers(), getTrustManagers()
	 *         and getSecureRandom().
	 * @throws SSLContextFactoryException
	 */
	public SSLContext buildSSLContext(String contextProtocol)
			throws SSLContextFactoryException {
		try {
			SSLContext sslContext;
			if (this.contextProvider != null) {
				sslContext = SSLContext.getInstance(contextProtocol,
						this.contextProvider);
			} else {
				sslContext = SSLContext.getInstance(contextProtocol);
			}
			sslContext.init(getKeyManagers(), getTrustManagers(),
					getSecureRandom());
			return sslContext;
		} catch (KeyManagementException e) {
			throw new SSLContextFactoryException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new SSLContextFactoryException(e);
		}
	}

	/**
	 * Returns the KeyManagers to be used for initialising the SSLContext.
	 * Defaults to null.
	 * 
	 * @return The KeyManagers to be used for initialising the SSLContext.
	 * @throws SSLContextFactoryException
	 */
	public KeyManager[] getKeyManagers() throws SSLContextFactoryException {
		return null;
	}

	/**
	 * Returns the TrustManagers to be used for initialising the SSLContext.
	 * Defaults to null.
	 * 
	 * @return The TrustManagers to be used for initialising the SSLContext.
	 * @throws SSLContextFactoryException
	 */
	public TrustManager[] getTrustManagers() throws SSLContextFactoryException {
		return null;
	}

	/**
	 * Sets the SecureRandom to be used for initialising the SSLContext.
	 * 
	 * @param secureRandom
	 *            the secureRandom to set
	 */
	public void setSecureRandom(SecureRandom secureRandom) {
		this.secureRandom = secureRandom;
	}

	/**
	 * Returns the SecureRandom to be used for initialising the SSLContext.
	 * Defaults to SecureRandom.getInstance(...) if defaultSecureRandomAlgorithm
	 * has been set (with optional provider) or null otherwise. It will only try
	 * to create a new SecureRandom from the default value if the current value
	 * is null. Reset it to null if you want to re-create a new SecureRandom
	 * from the default values.
	 * 
	 * @return The SecureRandom to be used for initialising the SSLContext.
	 * @throws SSLContextFactoryException
	 */
	public SecureRandom getSecureRandom() throws SSLContextFactoryException {
		if ((this.secureRandom == null)
				&& (this.defaultSecureRandomAlgorithm != null)) {
			try {
				if (this.defaultSecureRandomProvider != null) {
					this.secureRandom = SecureRandom.getInstance(
							this.defaultSecureRandomAlgorithm,
							this.defaultSecureRandomProvider);
				} else {
					this.secureRandom = SecureRandom
							.getInstance(this.defaultSecureRandomAlgorithm);
				}
			} catch (NoSuchAlgorithmException e) {
				throw new SSLContextFactoryException(
						"Error initialising SecureRandom.", e);
			}
		}
		return this.secureRandom;
	}

	/**
	 * SSLContextFactories are likely to contain sensitive information; cloning
	 * is therefore not allowed.
	 */
	protected final SSLContextFactory clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException();
	}

	/**
	 * This class is a wrapper exception for most exceptions that can occur when
	 * using an SSLContextFactory.
	 * 
	 * @author Bruno Harbulot &lt;Bruno.Harbulot@manchester.ac.uk&gt;
	 * 
	 */
	public class SSLContextFactoryException extends Exception {
		private static final long serialVersionUID = 1L;
		public static final String message = "Exception in SSLContextFactory";

		public SSLContextFactoryException(Exception e) {
			super(SSLContextFactoryException.message, e);
		}

		public SSLContextFactoryException(String message) {
			super(SSLContextFactoryException.message + " " + message);
		}

		public SSLContextFactoryException(String message, Exception e) {
			super(SSLContextFactoryException.message + " " + message, e);
		}
	}
}
