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

package jsslutils.sslcontext.keymanagers;

import java.net.Socket;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import javax.net.ssl.X509KeyManager;

import jsslutils.sslcontext.X509KeyManagerWrapper;

/**
 * This is an X509KeyManager that will always choose the server alias name it
 * has been constructed with.
 * 
 * @author Bruno Harbulot.
 */
public class FixedServerAliasKeyManager implements X509KeyManager {
	private X509KeyManager keyManager;
	private String alias;

	/**
	 * Creates a new instance from an existing X509KeyManager.
	 * 
	 * @param keyManager
	 *            X509KeyManager to wrap.
	 * @param alias
	 *            alias to use to choose a key for the server sockets.
	 */
	public FixedServerAliasKeyManager(X509KeyManager keyManager, String alias) {
		this.keyManager = keyManager;
		this.alias = alias;
	}

	/**
	 * Relays the call to the wrapped X509KeyManager.
	 * 
	 * @see javax.net.ssl.X509KeyManager#chooseClientAlias(java.lang.String[],
	 *      java.security.Principal[], java.net.Socket)
	 */
	public String chooseClientAlias(String[] keyType, Principal[] issuers,
			Socket socket) {
		return this.keyManager.chooseClientAlias(keyType, issuers, socket);
	}

	/**
	 * Returns the alias this instance has been constructed with, regardless of
	 * any other parameters.
	 * 
	 * @return The alias passed to the constructor.
	 * @see javax.net.ssl.X509KeyManager#chooseServerAlias(java.lang.String,
	 *      java.security.Principal[], java.net.Socket)
	 */
	public String chooseServerAlias(String keyType, Principal[] issuers,
			Socket socket) {
		return this.alias;
	}

	/**
	 * Relays the call to the wrapped X509KeyManager.
	 * 
	 * @see javax.net.ssl.X509KeyManager#getCertificateChain(java.lang.String)
	 */
	public X509Certificate[] getCertificateChain(String alias) {
		return this.keyManager.getCertificateChain(alias);
	}

	/**
	 * Relays the call to the wrapped X509KeyManager.
	 * 
	 * @see javax.net.ssl.X509KeyManager#getClientAliases(java.lang.String,
	 *      java.security.Principal[])
	 */
	public String[] getClientAliases(String keyType, Principal[] issuers) {
		return this.keyManager.getClientAliases(keyType, issuers);
	}

	/**
	 * Relays the call to the wrapped X509KeyManager.
	 * 
	 * @see javax.net.ssl.X509KeyManager#getPrivateKey(java.lang.String)
	 */
	public PrivateKey getPrivateKey(String alias) {
		return this.keyManager.getPrivateKey(alias);
	}

	/**
	 * Relays the call to the wrapped X509KeyManager.
	 * 
	 * @see javax.net.ssl.X509KeyManager#getServerAliases(java.lang.String,
	 *      java.security.Principal[])
	 */
	public String[] getServerAliases(String keyType, Principal[] issuers) {
		return this.keyManager.getServerAliases(keyType, issuers);
	}

	/**
	 * Wrapper factory class that wraps existing X509KeyManagers into
	 * FixedServerAliasKeyManager, with the alias passed to the constructor.
	 * 
	 * @author Bruno Harbulot.
	 */
	public static class Wrapper implements X509KeyManagerWrapper {
		private String alias;

		/**
		 * Creates a new FixedServerAliasKeyManager wrapper, using the alias
		 * passed to this constructor.
		 * 
		 * @param alias
		 *            alias to choose for the server socket.
		 */
		public Wrapper(String alias) {
			this.alias = alias;
		}

		/**
		 * Builds an X509KeyManager from another X509KeyManager.
		 * 
		 * @param keyManager
		 *            original X509KeyManager.
		 * @return wrapped X509KeyManager.
		 */
		public X509KeyManager wrapKeyManager(X509KeyManager keyManager) {
			return new FixedServerAliasKeyManager(keyManager, alias);
		}
	}
}
