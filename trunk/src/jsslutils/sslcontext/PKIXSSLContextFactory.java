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

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRL;
import java.security.cert.CRLException;
import java.security.cert.CertStore;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXParameters;
import java.security.cert.X509CRL;
import java.security.cert.X509CertSelector;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import javax.net.ssl.CertPathTrustManagerParameters;
import javax.net.ssl.ManagerFactoryParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import sun.security.util.DerValue;

/**
 * This class is a factory that provides methods for creating an SSLContext
 *  configured with the settings set in this factory: using the PKIX
 *  algorithm for both the key manager and the trust manager. These managers
 *  are created from the KeyStores passed to the constructor.
 *  This implementation build a trust store that supports revocation and 
 *  CRLs, see the CRL-related methods.
 * 
 * @author Bruno Harbulot
 * 
 */
public class PKIXSSLContextFactory extends X509SSLContextFactory {
	protected boolean enableRevocation;
	protected Set<CRL> crlCollection = new HashSet<CRL>();
	private CertificateFactory certificateFactory = null;
	
	/**
	 * Builds an SSLContextFactory using the PKIX algorithm in the 
	 *  TrustManagerFactory.
	 * @param keyStore KeyStore that contains the key.
	 * @param keyPassword password to the key.
	 * @param trustStore KeyStore that contains the trusted X.509 certificates.
	 * @param enableRevocation sets whether certificate revocation should be 
	 *  enabled.
	 */
	public PKIXSSLContextFactory(KeyStore keyStore, String keyPassword, KeyStore trustStore, boolean enableRevocation) {
		super(keyStore, keyPassword, trustStore);
		this.enableRevocation = enableRevocation;
	}
	/**
	 * Builds an SSLContextFactory using the PKIX algorithm in the 
	 *  TrustManagerFactory. Certificate revocation is enabled by default.
	 * @param keyStore KeyStore that contains the key.
	 * @param keyPassword password to the key.
	 * @param trustStore KeyStore that contains the trusted X.509 certificates.
	 */
	public PKIXSSLContextFactory(KeyStore keyStore, String keyPassword, KeyStore trustStore) {
		this(keyStore, keyPassword, trustStore, true);
	}
	
	/**
	 * Builds TrustManagers from the trust store provided in the constructor, using
	 *  a PKIX TrustManagerFactory. The TrustManagerFactory parameters used
	 *  are those provided by getTrustParams().
	 * @return PKIX-based trust managers corresponding to the trust store.
	 */
	@Override
	public TrustManager[] getTrustManagers() throws SSLContextFactoryException {
		try {
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
			ManagerFactoryParameters trustParams = getTrustParams();
			tmf.init(trustParams);
			return tmf.getTrustManagers();
		} catch (NoSuchAlgorithmException e) {
			throw new SSLContextFactoryException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new SSLContextFactoryException(e);
		}
	}
	
	/**
	 * Returns the ManagerFactoryParameters used for initialising the 
	 *  TrustManagerFactory in getTrustManagers(). You can override it, but
	 *  the default behaviour is to build a CertPathTrustManagerParameters
	 *  from the PKIXParameters returned by getPKIXParameters().
	 * @return ManagerFactoryParameters used by getTrustManagers().
	 * @throws SSLContextFactoryException
	 */
	protected ManagerFactoryParameters getTrustParams() throws SSLContextFactoryException {
		PKIXParameters pkixParams = getPKIXParameters();
		ManagerFactoryParameters trustParams = new CertPathTrustManagerParameters(pkixParams);
		return trustParams;
	}
	
	/**
	 * Returns the PKIXParameters used for initialising the 
	 *  ManagerFactoryParameters in getTrustParams(). You can override it, but
	 *  the default behaviour is to build a PKIXBuilderParameters from the
	 *  trustStore, enable the revocation according to enableRevocation and
	 *  adds the CertStore provided by getCertStore().
	 * @return PKIXParameters used by getTrustParams()
	 * @throws SSLContextFactoryException
	 */
	protected PKIXParameters getPKIXParameters() throws SSLContextFactoryException {
		try {
			PKIXParameters pkixParams = new PKIXBuilderParameters(getTrustStore(),
				    new X509CertSelector());
			pkixParams.setRevocationEnabled(this.enableRevocation);
			pkixParams.addCertStore(getCertStore());
			return pkixParams;
		} catch (KeyStoreException e) {
			throw new SSLContextFactoryException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new SSLContextFactoryException(e);
		}
	}
	
	/**
	 * Returns the CertStore added to the PKIXParameters in 
	 *  getPKIXParameters(). You can override it, but the default behaviour
	 *  is to build a CertStore using the Collection of X509CRL obtained from
	 *  getCrlCollection(). Typical extensions would probably consist of
	 *  using an LDAP-based CertStore.
	 * @return CertStore used by getPKIXParameters().
	 * @throws SSLContextFactoryException
	 */
	protected CertStore getCertStore() throws SSLContextFactoryException {
		try {
			CollectionCertStoreParameters collecCertStoreParams = new CollectionCertStoreParameters(getCrlCollection());
			return CertStore.getInstance("Collection", collecCertStoreParams);
		} catch (InvalidAlgorithmParameterException e) {
			throw new SSLContextFactoryException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new SSLContextFactoryException(e);
		}
	}

	/**
	 * Returns the Collection of X509CRLs used to initialise the 
	 *  CollectionCertStoreParameters used in getCertStore().
	 * @return Collection of X509CRL ultimetely checked by the trust manager.
	 * @throws SSLContextFactoryException
	 */
	public Collection<? extends CRL> getCrlCollection() throws SSLContextFactoryException {
		return this.crlCollection;
	}

	/**
	 * Adds CRLs to the collection used by getCrlCollection() (and thus the 
	 *  trust manager by default).
	 * @param crlCollection collection of CRLs to add.
	 * @throws SSLContextFactoryException
	 */
	public void addCrlCollection(Collection<? extends CRL> crlCollection) throws SSLContextFactoryException {
		this.crlCollection.addAll(crlCollection);
	}
	/**
	 * Adds a CRL to the collection used by getCrlCollection() (and thus the 
	 *  trust manager by default).
	 * @param crl CRL to add.
	 * @throws SSLContextFactoryException
	 */
	public void addCrl(CRL crl) throws SSLContextFactoryException {
		this.crlCollection.add(crl);
	}

	/**
	 * Adds a CRL from a URL to the collection used by getCrlCollection() 
	 *  (and thus the trust manager by default).
	 * @param crlUrl URL of the CRL to fetch.
	 * @throws SSLContextFactoryException
	 */
	public void addRemoteCrl(String crlUrl) throws SSLContextFactoryException, IOException, MalformedURLException {
		crlCollection.add(fetchRemoteCrl(crlUrl));
	}
	
	/**
	 * Builds a CRL object from a URL.
	 * @param crlUrl URL of the CRL to fetch.
	 * @return X509CRL built from the representation obtained from this URL.
	 * @throws SSLContextFactoryException
	 * @throws IOException
	 * @throws MalformedURLException
	 */
	public CRL fetchRemoteCrl(String crlUrl) throws SSLContextFactoryException, IOException, MalformedURLException {
		try {
			if (this.certificateFactory == null) {
				this.certificateFactory = CertificateFactory.getInstance("X.509");
			}
			InputStream is = null;
			try {
				URL url = new URL(crlUrl);
				is = url.openStream();
				X509CRL crl = (X509CRL)this.certificateFactory.generateCRL(new BufferedInputStream(is));
				return crl;
			} finally {
				if (is != null) {
					is.close();
				}
			}
		} catch (CertificateException e) {
			throw new SSLContextFactoryException(e);
		} catch (CRLException e) {
			throw new SSLContextFactoryException(e);
		}
	}
	
	
	public static final String OID_CRL_Distribution_Points = "2.5.29.31";
	public static final String OID_Netscape_CA_Revocation_URL = "2.16.840.1.113730.1.4";
	public static final String OID_Netscape_Revocation_URL = "2.16.840.1.113730.1.3";
	protected static final String[] URL_OID = {
		OID_CRL_Distribution_Points,
		OID_Netscape_CA_Revocation_URL,
		OID_Netscape_Revocation_URL
	};
	/**
	 * Extracts a Collection of Strings from various CRL-related OIDs in a
	 *  X.509 certificate.
	 *   <ul><li>OID CRL Distribution Points: 2.5.29.31</li>
	 *       <li>OID Netscape CA Revocation URL: 2.16.840.1.113730.1.4</li>
	 *       <li>OID Netscape Revocation URL: 2.16.840.1.113730.1.3</li>
	 *   </ul>
	 * @param x509Certificate certificate from which to extract these OIDs.
	 * @return URLs to CRLs.
	 * @throws IOException
	 */
	public static Collection<String> extractCrlUrlCollection(X509Certificate x509Certificate) throws IOException {
		Set<String> criticalOIDs = x509Certificate.getCriticalExtensionOIDs();
		Collection<String> crlUrls = new ArrayList<String>(); 
		for (String oid: URL_OID) {
			try {
				byte[] oidArray = x509Certificate.getExtensionValue(oid);
				if (oidArray != null)
					crlUrls.add(new DerValue(oidArray).getAsString());
			} catch (IOException e) {
				if (criticalOIDs.contains(oid))
					throw e;
			}
		}
		return crlUrls;
	}
}
