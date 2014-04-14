/*	$Id$
 *  Copyright (c) 2009 Spacebel S.A.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package be.spacebel.webservice.authentication;

import java.util.*;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;

/**
 * The class LDAPAccess provides access methods to LDAP registry; it
 * encapsulates all the details of LDAP connection and data access.
 * 
 * @author The Hoa Nguyen
 * 
 */

public class ConfigurationUtils {

	public static final String CONFIRMATION_METHOD_BEARER = "urn:oasis:names:tc:SAML:1.0:cm:bearer";
	public static final String AUTHENTICATION_METHOD = "urn:oasis:names:tc:SAML:1.0:am:password";

	// Assertion node defined in the OGC 07-118 (up to 0.0.4)
	public static final String ASSERTION_NODE_NAMESPACE = "http://earth.esa.int/um/eop/saml";
	public static final String ASSERTION_NODE_NAME = "Assertion";

	private static final String CONF_FILENAME = "authentication-service";
	private static final String FEDERATED_STS_CONF_FILENAME = "federated-sts";

	private static Logger logger = Logger.getLogger(ConfigurationUtils.class);;

	private static ResourceBundle conf = null;
	private static ResourceBundle federatedSTSConf = null;

	static {
		try {
			conf = ResourceBundle.getBundle(CONF_FILENAME);
			PropertyConfigurator.configure(ConfigurationUtils
					.getProperty("LOG4J_CONFIG_LOCATION"));
		} catch (Exception ex) {
			ex.printStackTrace();
			logger
					.error("error while loading the file authentication-service.properties. Please check the file path is included in the java classpath");
		}
		try {

			federatedSTSConf = ResourceBundle
					.getBundle(FEDERATED_STS_CONF_FILENAME);

		} catch (Exception ex) {
			logger.info("no STS federation (no " + FEDERATED_STS_CONF_FILENAME
					+ " file)");
		}

	}

	/**
	 * get the configuration property defined by the input parameter key.
	 * 
	 * @param key
	 * @return value of the property
	 */

	public static String getProperty(String key) {
		return conf.getString(key).trim();
	}

	/**
	 * get the configuration property defined by the input parameter key.
	 * 
	 * @param key
	 * @return value of the property
	 * @throws Exception 
	 * @throws Exception
	 */

	public static String getURLOfFederatedSTS(String urnOfFederatedSTS) throws Exception {

		try {
			return federatedSTSConf.getString(urnOfFederatedSTS).trim();
		} catch (RuntimeException e) {
			String msg = "Unknown federated STS '" + urnOfFederatedSTS + "'";
			if (federatedSTSConf == null) {
				msg += " (no STS federation support)";
			}
			throw new Exception(msg);
		}
	}

}
