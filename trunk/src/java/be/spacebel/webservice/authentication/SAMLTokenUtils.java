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

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttributes;

import org.apache.log4j.Logger;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLAttribute;
import org.opensaml.SAMLAttributeStatement;
import org.opensaml.SAMLAuthenticationStatement;
import org.opensaml.SAMLException;
import org.opensaml.SAMLNameIdentifier;
import org.opensaml.SAMLSubject;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

/**
 * The SAMLTokenUtils class provides a method to build a SAML token.
 * 
 * @author Pierre Denis (pds)
 * @author Minh Nguyen Quang
 * 
 */
public class SAMLTokenUtils {

	private Logger logger = Logger.getLogger(this.getClass().getName());

	private long samlTokenExpiryPeriodInMs;
	private Map<String, String> ldapAttributesConf;
	private String subjectIdAttributeName = null;

	/**
	 * Constructs a new instance of SAMLTokenUtils
	 * 
	 */

	SAMLTokenUtils() {

		try {
			InputStream inputStream = getClass().getResourceAsStream(
					"/saml-ldap-attributes-mapping.properties");
			BufferedReader br = new BufferedReader(new InputStreamReader(
					inputStream));
			ldapAttributesConf = new LinkedHashMap<String, String>();
			String currentLine = null;
			while ((currentLine = br.readLine()) != null) {
				currentLine = currentLine.trim();
				if (!"".equals(currentLine) && !currentLine.startsWith("#")
						&& currentLine.indexOf("=") != -1) {

					String[] splittedLine = currentLine.split("=");
					ldapAttributesConf.put(splittedLine[0].trim(),
							splittedLine[1].trim());
					if (subjectIdAttributeName == null) {
						subjectIdAttributeName = splittedLine[1].trim();
						logger.info("Subject identifier attribute: " + subjectIdAttributeName);
					}

				}
			}
			br.close();

			samlTokenExpiryPeriodInMs = 1000 * Integer
					.parseInt(ConfigurationUtils
							.getProperty("SAML_TOKEN_EXPIRY_PERIOD"));
		} catch (Exception e) {
			logger.error("error while loading the " + this.getClass().getName()
					+ ", details: " + e.getMessage());
			e.printStackTrace();
		}
	}

	/**
	 * Builds and returns a SAML assertion based on the attributes of the given
	 * user data.
	 * 
	 * @param userData
	 *            data of the user to be put in the token
	 * 
	 * @return a DOM element with the SAML assertion
	 * 
	 * @throws SAMLException
	 *             if probleme occurs in the generation of the SAML assertion
	 * @throws NamingException
	 *             if problem occurs to retrieve attributes from given user data
	 */
	public Element buildSAMLToken(Attributes attributes) throws SAMLException,
			NamingException {

		Date creationTime = new Date();

		Date expirationTime = new Date(creationTime.getTime()
				+ samlTokenExpiryPeriodInMs);

		Element keyInfoElem = null;
		SAMLNameIdentifier subjectNameId = new SAMLNameIdentifier();
		SAMLNameIdentifier subjectNameId2 = new SAMLNameIdentifier();

		SAMLAssertion samlAssertion = new SAMLAssertion(ConfigurationUtils
				.getProperty("SAML_ASSERTION_ID_PREFIX"), creationTime,
				expirationTime, null, null, null);

		samlAssertion.setIssuer(ConfigurationUtils
				.getProperty("SAML_ASSERTION_ISSUER"));

		SAMLAttributeStatement attributeStatement = new SAMLAttributeStatement();

		NamingEnumeration<Attribute> az = (NamingEnumeration<Attribute>) attributes
				.getAll();
		boolean subjectNameIdIsUnset = true;
		while (az.hasMore()) {
			Attribute attr = az.next();

			SAMLAttribute samlAttribute = new SAMLAttribute();
			samlAttribute.setName(attr.getID());
			samlAttribute
					.setNamespace(ConfigurationUtils.ASSERTION_NODE_NAMESPACE);
			String[] values = new String[] { (String) attr.get() };
			if (subjectNameIdIsUnset) {
				subjectNameId.setName(values[0]);
				subjectNameId2.setName(values[0]);
				subjectNameIdIsUnset = false;
			}

			samlAttribute.setValues(Arrays.asList(values));

			attributeStatement.addAttribute(samlAttribute);
		}
		
		String[] values = new String[] { (String) attributes.get(subjectIdAttributeName).get() };
		String userId = values[0];
		subjectNameId.setName(userId);
		subjectNameId2.setName(userId);
		SAMLSubject subject = new SAMLSubject(subjectNameId, Arrays
				.asList(SAMLSubject.CONF_BEARER), null, keyInfoElem);
		SAMLSubject subject2 = new SAMLSubject(subjectNameId2, Arrays
				.asList(SAMLSubject.CONF_BEARER), null, keyInfoElem);

		SAMLAuthenticationStatement samlAuthenticationStatement = new SAMLAuthenticationStatement();
		samlAuthenticationStatement.setAuthInstant(creationTime);
		samlAuthenticationStatement
				.setAuthMethod(SAMLAuthenticationStatement.AuthenticationMethod_Password);
		samlAuthenticationStatement.setSubject(subject);
		samlAssertion.addStatement(samlAuthenticationStatement);

		attributeStatement.setSubject(subject2);

		samlAssertion.addStatement(attributeStatement);

		Node samlAssertionNode = samlAssertion.toDOM();

		return (Element) samlAssertionNode;
	}

	/**
	 * to return a set of user attributes to be included in the SAML token.
	 * Note: the corresponding LDAP attributes' names could be different to the
	 * SAML attributes'names. The mapping is done via a configuration file.
	 * 
	 * @return
	 */
	public Attributes getSAMLAttributes(Attributes ldapAttributes) {

		BasicAttributes attributes = new BasicAttributes();
		try {
			for (String ldapAttributeName : ldapAttributesConf.keySet()) {
				String samlAtrributeName = ldapAttributesConf
						.get(ldapAttributeName);

				if (logger.isDebugEnabled()) {
					logger.debug("ldapAttributeName = "
							+ ldapAttributeName);
					logger.debug("samlAtrributeName = "
							+ samlAtrributeName);
				}
				Attribute ldapAttribute = ldapAttributes.get(ldapAttributeName);
				if (ldapAttribute != null) {
					attributes.put(samlAtrributeName, ldapAttribute.get(0)
							.toString());
				} else {
					logger.warn("attribute '" + ldapAttributeName
							+ "' is unknown in LDAP entry; '"
							+ samlAtrributeName + "' is skipped in SAML token");
				}
			}
		} catch (NamingException e) {
			logger
					.error("error while converting ldap attributes to saml attributes");
			e.printStackTrace();
			return null;
		}
		return attributes;
	}

}
