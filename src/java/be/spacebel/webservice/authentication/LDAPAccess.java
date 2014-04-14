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

import java.util.Hashtable;
import java.util.MissingResourceException;
import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchResult;

import org.apache.log4j.Logger;

/**
 * The class LDAPAccess provides access methods to LDAP registry; it
 * encapsulates all the details of LDAP connection and data access.
 * 
 * @author The Hoa Nguyen
 * 
 */
public class LDAPAccess {

	private Logger logger = Logger.getLogger(LDAPAccess.class);

	private String registrationStateAttributeName = null;

	private String registrationStateAttributeValue = null;

	/**
	 * create a new instance of LDAPAccess
	 * 
	 */
	LDAPAccess() {
		try {
			registrationStateAttributeName = ConfigurationUtils
					.getProperty("REGISTRATION_STATE_ATTRIBUTE_NAME");
			registrationStateAttributeValue = ConfigurationUtils
					.getProperty("REGISTRATION_STATE_ATTRIBUTE_VALUE");
			logger
					.info("enforced registration state check for authentication: "
							+ registrationStateAttributeName
							+ " = '"
							+ registrationStateAttributeValue + "'");
		} catch (MissingResourceException e) {
			logger.info("no registration state check for authentication");
			registrationStateAttributeName = null;
			registrationStateAttributeValue = null;
		}
	}

	/**
	 * Check registration state within the given attributes
	 * 
	 * @param attrs
	 *            the attributes to check
	 * @throws NamingException
	 *             if the registration state attribute is missing
	 * @throws AuthenticationException
	 *             if the registration state attribute has not the required
	 *             value
	 */
	void checkRegistrationState(Attributes attrs) throws NamingException,
			AuthenticationException {
		if (registrationStateAttributeName != null) {
			// a check is required on registration state
			Attribute registrationStateAttribute = attrs
					.get(registrationStateAttributeName);
			if (registrationStateAttribute == null) {
				logger.error("missing LDAP attribute '"
						+ registrationStateAttributeName + "'");
				throw new NamingException();
			}
			String actualRegistrationStateAttributeValue = (String) attrs.get(
					registrationStateAttributeName).get();
			if (!registrationStateAttributeValue
					.equals(actualRegistrationStateAttributeValue)) {
				// actual registration state of the authenticated user is
				// missing or invalid
				throw new AuthenticationException("user not registered");
			}
		}
	}

	/**
	 * Authenticate user credential using the service LDAP directory and returns
	 * the associated LDAP attributes
	 * 
	 * @param username
	 *            user name of the user to authenticate
	 * @param password
	 *            password of the user to authenticate
	 * @return user data attributes
	 * @throws AuthenticationException
	 *             if the user is not authenticated with the given
	 *             username/password or has not the required registration state
	 */

	public Attributes authenticate(String username, String password)
			throws AuthenticationException {

		// prepare environment context
		Hashtable<String, String> env = new Hashtable<String, String>();
		env.put(Context.INITIAL_CONTEXT_FACTORY,
				"com.sun.jndi.ldap.LdapCtxFactory");
		env
				.put(Context.PROVIDER_URL, ConfigurationUtils
						.getProperty("LDAPURL"));
		env.put(Context.SECURITY_PRINCIPAL, "cn=" + username + ","
				+ ConfigurationUtils.getProperty("LDAPSearchContext"));
		env.put(Context.SECURITY_CREDENTIALS, password);
		env.put(Context.SECURITY_AUTHENTICATION, "simple");

		InitialDirContext ctx;
		try {
			ctx = new InitialDirContext(env);
			// user credential is validated, populate the user data.
			Attributes attrs = ctx.getAttributes("cn=" + username + ","
					+ ConfigurationUtils.getProperty("LDAPSearchContext"));
			checkRegistrationState(attrs);
			return attrs;
		} catch (NamingException e) {
			throw new AuthenticationException(
					"Authentication Fail: Invalid Credentials for user '"
							+ username + "'");
		}
	}

	/**
	 * returns the LDAP attributes associated to given user name
	 * 
	 * @param username
	 *            user name of the user
	 * @return user data attributes
	 * @throws AuthenticationException
	 *             if the user is not found or has not the required registration
	 *             state
	 */
	public Attributes getLdapAttributes(String username)
			throws AuthenticationException {

		try {

			String connectionURL = ConfigurationUtils.getProperty("LDAPURL");
			String principal = ConfigurationUtils.getProperty("LDAPPrincipal");
			String credentials = ConfigurationUtils
					.getProperty("LDAPCredentials");
			String searchContext = ConfigurationUtils
					.getProperty("LDAPSearchContext");

			Hashtable<String, String> ldapEnvironment = new Hashtable<String, String>();
			ldapEnvironment.put(Context.INITIAL_CONTEXT_FACTORY,
					"com.sun.jndi.ldap.LdapCtxFactory");
			ldapEnvironment.put(Context.PROVIDER_URL, connectionURL);
			ldapEnvironment.put(Context.SECURITY_PRINCIPAL, principal);
			ldapEnvironment.put(Context.SECURITY_CREDENTIALS, credentials);
			ldapEnvironment.put(Context.SECURITY_AUTHENTICATION, "simple");

			InitialDirContext initialDirContext = new InitialDirContext(
					ldapEnvironment);

			Attributes matchAttrs = new BasicAttributes();
			matchAttrs.put("cn", username);
			// matchAttrs.put("objectClass", LDAP_USER_PROFILE_OBJECT_CLASS);

			// Search for objects that have those matching attributes
			NamingEnumeration<SearchResult> answer = initialDirContext.search(
					searchContext, matchAttrs);

			if (answer.hasMore()) {
				SearchResult sr = answer.next();
				Attributes attributes = sr.getAttributes();
				checkRegistrationState(attributes);
				return attributes;
			}

		} catch (Exception e) {
			logger.debug("error occured while getting data of the user "
					+ username + ", details: " + e.getMessage());
			e.printStackTrace();
		}
		throw new AuthenticationException(
				"Authentication Fail: Invalid Credentials");
	}

}