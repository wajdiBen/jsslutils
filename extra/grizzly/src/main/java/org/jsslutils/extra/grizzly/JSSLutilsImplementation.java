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

import java.net.Socket;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;

import com.sun.grizzly.util.net.SSLImplementation;
import com.sun.grizzly.util.net.SSLSupport;
import com.sun.grizzly.util.net.ServerSocketFactory;

/**
 * This is an SSLImplementation extending the default JSSEImplementation to use
 * <a href="http://www.jsslutils.org">jSSLutils</a>.
 * 
 * @author Bruno Harbulot
 */
public class JSSLutilsImplementation extends SSLImplementation {
	private final static Logger logger = Logger
			.getLogger("org.jsslutils.extra.grizzly");

	private final JSSLutilsFactory factory;

	public JSSLutilsImplementation() {
		this.factory = new JSSLutilsFactory();
	}

	@Override
	public String getImplementationName() {
		return "jsslutils";
	}

	@Override
	public ServerSocketFactory getServerSocketFactory() {
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(JSSLutilsImplementation.class.getName()
					+ "#getServerSocketFactory()");
		}
		return factory.getSocketFactory();
	}

	@Override
	public SSLSupport getSSLSupport(Socket s) {
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(JSSLutilsImplementation.class.getName()
					+ "#getSSLSupport()");
		}
		return factory.getSSLSupport(s);
	}

	@Override
	public SSLSupport getSSLSupport(SSLEngine sslEngine) {
		if (logger.isLoggable(Level.FINE)) {
			logger.fine(JSSLutilsImplementation.class.getName()
					+ "#getSSLSupport()");
		}
		return factory.getSSLSupport(sslEngine);
	}
}
