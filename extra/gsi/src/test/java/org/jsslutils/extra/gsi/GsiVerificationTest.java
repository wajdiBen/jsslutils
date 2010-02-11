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

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.TimeZone;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 * @author Bruno Harbulot.
 */
public class GsiVerificationTest {

	public final static char[] KEYSTORE_PASSWORD = "testtest".toCharArray();

	private X509Certificate[] preRfcProxyCert;
	private X509Certificate[] rfc3820ProxyCert;
	private X509Certificate[] legacyProxyCert;
	private X509Certificate[] limitedLegacyProxyCert;

	private Date preRfcProxyCertDate;
	private Date rfc3820ProxyCertDate;
	private Date legacyProxyCertDate;
	private Date limitedLegacyProxyCertDate;

	@Before
	public void loadTestCertificates() throws Exception {
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
		cal.set(2010, 01, 10, 19, 00);
		Date date = cal.getTime();

		preRfcProxyCert = certificateFactory.generateCertificates(
				GsiVerificationTest.class.getResourceAsStream("prerfc_cert.pem"))
				.toArray(new X509Certificate[] {});
		preRfcProxyCertDate = date;
		legacyProxyCert = certificateFactory.generateCertificates(
				GsiVerificationTest.class
						.getResourceAsStream("legacy_cert.pem")).toArray(
				new X509Certificate[] {});
		legacyProxyCertDate = date;
		limitedLegacyProxyCert = certificateFactory.generateCertificates(
				GsiVerificationTest.class
						.getResourceAsStream("legacy_limited_cert.pem"))
				.toArray(new X509Certificate[] {});
		limitedLegacyProxyCertDate = date;
		rfc3820ProxyCert = certificateFactory.generateCertificates(
				GsiVerificationTest.class
						.getResourceAsStream("rfc3820_cert.pem")).toArray(
				new X509Certificate[] {});
		rfc3820ProxyCertDate = date;
	}

	@Test
	public void testVerifyProxyCert() throws Exception {
		CertificateException e;

		e = GsiWrappingTrustManager.verifyProxyCertificate(legacyProxyCert, 1,
				legacyProxyCertDate);
		displayException(e);
		assertNull(e);

		e = GsiWrappingTrustManager.verifyProxyCertificate(
				limitedLegacyProxyCert, 1, limitedLegacyProxyCertDate);
		displayException(e);
		assertNull(e);

		e = GsiWrappingTrustManager.verifyProxyCertificate(preRfcProxyCert, 1,
				preRfcProxyCertDate);
		displayException(e);
		assertNull(e);

		e = GsiWrappingTrustManager.verifyProxyCertificate(rfc3820ProxyCert, 1,
				rfc3820ProxyCertDate);
		displayException(e);
		assertNull(e);
	}

	@Test
	public void testVerifyProxyCertOnlyLegacy() throws Exception {
		CertificateException e;

		e = GsiWrappingTrustManager.verifyProxyCertificate(legacyProxyCert, 1,
				true, false, false, legacyProxyCertDate);
		displayException(e);
		assertNull(e);

		e = GsiWrappingTrustManager.verifyProxyCertificate(
				limitedLegacyProxyCert, 1, true, false, false,
				limitedLegacyProxyCertDate);
		displayException(e);
		assertNull(e);

		e = GsiWrappingTrustManager.verifyProxyCertificate(preRfcProxyCert, 1,
				true, false, false, preRfcProxyCertDate);
		displayException(e);
		assertNotNull(e);

		e = GsiWrappingTrustManager.verifyProxyCertificate(rfc3820ProxyCert, 1,
				true, false, false, rfc3820ProxyCertDate);
		displayException(e);
		assertNotNull(e);
	}

	@Test
	public void testVerifyLegacyProxyCert() throws Exception {
		CertificateException e;

		e = GsiWrappingTrustManager.verifyLegacyProxyCertificate(
				legacyProxyCert, 1, legacyProxyCertDate);
		displayException(e);
		assertNull(e);

		e = GsiWrappingTrustManager.verifyLegacyProxyCertificate(
				limitedLegacyProxyCert, 1, limitedLegacyProxyCertDate);
		displayException(e);
		assertNull(e);

		e = GsiWrappingTrustManager.verifyLegacyProxyCertificate(preRfcProxyCert,
				1, preRfcProxyCertDate);
		displayException(e);
		assertNotNull(e);

		e = GsiWrappingTrustManager.verifyLegacyProxyCertificate(
				rfc3820ProxyCert, 1, rfc3820ProxyCertDate);
		displayException(e);
		assertNotNull(e);
	}

	@Test
	public void testVerifyRfc3820ProxyCert() throws Exception {
		CertificateException e;

		e = GsiWrappingTrustManager.verifyRfc3820ProxyCertificate(
				legacyProxyCert, 1, legacyProxyCertDate);
		displayException(e);
		assertNotNull(e);

		e = GsiWrappingTrustManager.verifyRfc3820ProxyCertificate(
				limitedLegacyProxyCert, 1, limitedLegacyProxyCertDate);
		displayException(e);
		assertNotNull(e);

		e = GsiWrappingTrustManager.verifyRfc3820ProxyCertificate(preRfcProxyCert,
				1, preRfcProxyCertDate);
		displayException(e);
		assertNotNull(e);

		e = GsiWrappingTrustManager.verifyRfc3820ProxyCertificate(
				rfc3820ProxyCert, 1, rfc3820ProxyCertDate);
		displayException(e);
		assertNull(e);
	}

	@Test
	public void testVerifyGt4ProxyCert() throws Exception {
		CertificateException e;

		e = GsiWrappingTrustManager.verifyPreRfcProxyCertificate(legacyProxyCert,
				1, legacyProxyCertDate);
		displayException(e);
		assertNotNull(e);

		e = GsiWrappingTrustManager.verifyPreRfcProxyCertificate(
				limitedLegacyProxyCert, 1, limitedLegacyProxyCertDate);
		displayException(e);
		assertNotNull(e);

		e = GsiWrappingTrustManager.verifyPreRfcProxyCertificate(preRfcProxyCert, 1,
				preRfcProxyCertDate);
		displayException(e);
		assertNull(e);

		e = GsiWrappingTrustManager.verifyPreRfcProxyCertificate(rfc3820ProxyCert,
				1, rfc3820ProxyCertDate);
		displayException(e);
		assertNotNull(e);
	}

	private static void displayException(Exception e) {
		if (e == null) {
			System.out.println("* No Exception");
		} else {
			System.out.print("* ");
			e.printStackTrace(System.out);
		}
	}
}
