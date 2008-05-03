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

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;

/**
 * This class is a factory that provides methods for creating an SSLContext
 *  configured with the settings set in this factory.
 *  It creates and initialises the SSLContext with
 *   init(getKeyManagers(), getTrustManagers(), getSecureRandom()), which
 *   all default to null. These three methods can be overridden.
 * 
 * @author Bruno Harbulot
 * 
 */
public class SSLContextFactory {
	private String contextProtocol = "SSLv3";
	private Provider contextProvider = null;
	private String contextProviderName = null;
	
	/**
	 * Sets the Provider used for creating the SSLContext (defaults to null).
	 * @param contextProvider Provider used to create the SSLContext.
	 */
	public void setContextProvider(Provider contextProvider) {
		this.contextProvider = contextProvider;
		this.contextProviderName = null;
	}
	/**
	 * Returns the Provider that is used for creating the SSLContext.
	 * @return Provider that is used for creating the SSLContext.
	 */
	public Provider getContextProvider() {
		return this.contextProvider;
	}
	/**
	 * Sets the name of the Provider used for creating the SSLContext 
	 *  (defaults to null). It is only used if there is no Provider set
	 *  using setContextProvider(Provider).
	 * @param contextProviderName name of the Provider to use.
	 */
	public void setContextProviderName(String contextProviderName) {
		this.contextProviderName = contextProviderName;
		this.contextProvider = null;
	}
	/**
	 * Returns the name of the provider that is used for creating the 
	 *  SSLContext, if one is set. If there is an actual provider set,
	 *  Provider.getName() is used, otherwise, it returns the 
	 *  context provider name, set as a String.
	 * @return Name of the context Provider.
	 */
	public String getContextProviderName() {
		return (this.contextProvider != null) ? this.contextProvider.getName() : this.contextProviderName;
	}
	/**
	 * Sets the protocol to be used for creating a new SSLContext. If no 
	 *  value is set, this defaults to "SSLv3".
	 * @param contextProtocol protocol to be used to create the SSLContext.
	 */
	public void setContextProtocol(String contextProtocol) {
		this.contextProtocol = contextProtocol;
	}
	/**
	 * Returns the protocol to be used for creating a new SSLContext.
	 * @return Protocol to be used to create the SSLContext.
	 */
	public String getContextProtocol() {
		return this.contextProtocol;
	}
	
	/**
	 * Creates a new SSLContext with the context protocol set with 
	 *  setContextProtocol(String). The default value is "SSLv3".
	 * @return SSLContext initialised with getKeyManagers(), 
	 *  getTrustManagers() and getSecureRandom().
	 * @throws SSLContextFactoryException
	 */
	public SSLContext newInitializedSSLContext() throws SSLContextFactoryException {
		return newInitializedSSLContext(contextProtocol);
	}
	/**
	 * Creates a new SSLContext initialised with getKeyManagers(), 
	 *  getTrustManagers() and getSecureRandom(). The provider is that
	 *  set up with setContextProvider() or setContextProviderName().
	 * @param contextProtocol SSLContext protocol.
	 * @return SSLContext initialised with getKeyManagers(), 
	 *  getTrustManagers() and getSecureRandom().
	 * @throws SSLContextFactoryException
	 */
	public SSLContext newInitializedSSLContext(String contextProtocol) throws SSLContextFactoryException {
		try {
			SSLContext sslContext;
			if (this.contextProvider != null) {
				sslContext = SSLContext.getInstance(contextProtocol, this.contextProvider);
			} else if (this.contextProviderName != null) {
				sslContext = SSLContext.getInstance(contextProtocol, this.contextProviderName);
			} else {
				sslContext = SSLContext.getInstance(contextProtocol);
			}
			sslContext.init(getKeyManagers(), getTrustManagers(), getSecureRandom());
			return sslContext;
		} catch (KeyManagementException e) {
			throw new SSLContextFactoryException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new SSLContextFactoryException(e);
		} catch (NoSuchProviderException e) {
			throw new SSLContextFactoryException(e);
		}
	}
	
	/**
	 * Returns the KeyManagers to be used for initialising the SSLContext.
	 *  Defaults to null.
	 * @return The KeyManagers to be used for initialising the SSLContext.
	 * @throws SSLContextFactoryException
	 */
	protected KeyManager[] getKeyManagers() throws SSLContextFactoryException {
		return null;
	}
	/**
	 * Returns the TrustManagers to be used for initialising the SSLContext.
	 *  Defaults to null.
	 * @return The TrustManagers to be used for initialising the SSLContext.
	 * @throws SSLContextFactoryException
	 */
	protected TrustManager[] getTrustManagers() throws SSLContextFactoryException {
		return null;
	}
	/**
	 * Returns the SecureRandom to be used for initialising the SSLContext.
	 *  Defaults to null.
	 * @return The SecureRandom to be used for initialising the SSLContext.
	 * @throws SSLContextFactoryException
	 */
	protected SecureRandom getSecureRandom() throws SSLContextFactoryException {
		return null;
	}
	
	/**
	 * SSLContextFactories are likely to contain sensitive information;
	 * cloning is therefore not allowed.
	 */
	protected final SSLContextFactory clone() throws CloneNotSupportedException {
		throw new CloneNotSupportedException();
	}
	
	/**
	 * This class is a wrapper exception for most exceptions that can
	 *  occur when using an SSLContextFactory.
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
			super(SSLContextFactoryException.message+" "+message);
		}
		public SSLContextFactoryException(String message, Exception e) {
			super(SSLContextFactoryException.message+" "+message, e);
		}
	}
}
