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
package org.jsslutils.extra.apachetomcat5;

import org.apache.tomcat.util.net.ServerSocketFactory;
import org.apache.tomcat.util.net.jsse.*;

/**
 * This is an SSLImplementation extending the default JSSEImplementation to use
 * <a href="http://www.jsslutils.org">jSSLutils</a>.
 * 
 * @author Bruno Harbulot
 */
public class JSSLutilsImplementation extends JSSEImplementation {
	public JSSLutilsImplementation() throws ClassNotFoundException {

	}

	public String getImplementationName() {
		return "jsslutils";
	}

	public ServerSocketFactory getServerSocketFactory() {
		return new JSSLutilsJSSESocketFactory();
	}
}
