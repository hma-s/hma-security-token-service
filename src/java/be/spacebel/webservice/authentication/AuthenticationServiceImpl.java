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

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.MissingResourceException;

import javax.naming.AuthenticationException;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathFactory;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFactory;
import org.apache.axiom.soap.SOAPFault;
import org.apache.axiom.soap.SOAPFaultCode;
import org.apache.axiom.soap.SOAPFaultReason;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.deployment.util.Utils;
import org.apache.axis2.util.XMLUtils;
import org.apache.log4j.Logger;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.utils.Constants;
import org.opensaml.SAMLException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * The AuthenticationServiceImpl class implements the AuthenticationService
 * interface, i.e. it defines the implementation of all authentication
 * operations.
 * 
 * @author The Hoa Nguyen (tnn)
 * @author Pierre Denis (pds)
 * 
 */
public class AuthenticationServiceImpl implements AuthenticationService {

	private static final String WST_NAMESPACE_URI = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/";
	private static final String WSSE_NAMESPACE_URI = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	private static final String WSA_NAMESPACE_URI = "http://www.w3.org/2005/08/addressing";
	private static final String WSP_NAMESPACE_URI = "http://schemas.xmlsoap.org/ws/2004/09/policy";

	private Logger logger = Logger.getLogger(this.getClass().getName());

	private LDAPAccess ldapAccess = null;

	private EncryptionUtils encryptionUtils = null;

	private SAMLTokenUtils samlTokenUtils = null;

	private boolean addNonStandardAssertionElement = false;

	private boolean isEncryptionActive = true;

	private String localSTSURN = null;

	private DocumentBuilder db = null;

	private SOAPFactory soapFactory = null;

	private RSTUtils rstUtils = new RSTUtils();

	/**
	 * Constructs a new instance of AuthenticationServiceImpl by initializing
	 * the members.
	 * 
	 * @throws ParserConfigurationException
	 * @throws NamingException
	 *             LDAPAccess
	 * @throws KeyStoreException
	 * @throws XMLEncryptionException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws CertificateException
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * 
	 */
	public AuthenticationServiceImpl() throws NamingException,
			KeyStoreException, XMLEncryptionException,
			NoSuchAlgorithmException, UnrecoverableEntryException,
			CertificateException, IOException, ParserConfigurationException {
		if (logger.isDebugEnabled()) {
			logger.debug("AuthenticationServiceImpl:: enter");
		}
		ldapAccess = new LDAPAccess();
		encryptionUtils = new EncryptionUtils();
		samlTokenUtils = new SAMLTokenUtils();
		soapFactory = OMAbstractFactory.getSOAP11Factory();
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		db = dbf.newDocumentBuilder();

		try {
			if ("false".equalsIgnoreCase(ConfigurationUtils
					.getProperty("SAML_TOKEN_ENCRYPTION_ACTIVE"))) {
				isEncryptionActive = false;
			}
		} catch (MissingResourceException e) {
			// SAML_TOKEN_ENCRYPTION_ACTIVE missing in the configuration
			// take default isEncryptionActive = true
		}
		logger.info("encryption active : " + isEncryptionActive);

		try {
			if ("true".equalsIgnoreCase(ConfigurationUtils
					.getProperty("SAML_ASSERTION_ELEMENT"))) {
				addNonStandardAssertionElement = true;
			}
		} catch (MissingResourceException e) {
			// SAML_ASSERTION_ELEMENT missing in the configuration
			// take default addNonStandardAssertionElement = false
		}
		logger.info("SAML add non-standard assertion element : "
				+ addNonStandardAssertionElement);

		try {
			localSTSURN = ConfigurationUtils.getProperty("LOCAL_STS_URN");
			logger
					.info("STS is federated under the name '" + localSTSURN
							+ "'");
		} catch (MissingResourceException e) {
			logger.info("STS is not federated");
		}

		if (logger.isDebugEnabled()) {
			logger.debug("AuthenticationServiceImpl:: exit");
		}
	}

	private static OMElement getUsernameToken(OMElement rstElement)
			throws AxisFault {

		OMElement tokenTypeElement = rstElement
				.getFirstChildWithName(new QName(WST_NAMESPACE_URI, "TokenType"));
		if (tokenTypeElement == null) {
			throw new AxisFault(
					new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
					"The request was invalid or malformed (missing TokenType element)",
					new Exception());
		}
		String tokenType = tokenTypeElement.getText().trim();
		if (!(tokenType
				.equals("http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"))) {
			throw new AxisFault(new QName(WST_NAMESPACE_URI, "InvalidRequest",
					"wst"),
					"The request was invalid or malformed (unsupported token type '"
							+ tokenType + "')", new Exception());
		}
		OMElement requestTypeElement = rstElement
				.getFirstChildWithName(new QName(WST_NAMESPACE_URI,
						"RequestType"));
		if (requestTypeElement == null) {
			throw new AxisFault(
					new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
					"The request was invalid or malformed (missing RequestType element)",
					new Exception());
		}
		String requestType = requestTypeElement.getText().trim();
		if (!(requestType
				.equals("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue"))) {
			throw new AxisFault(new QName(WST_NAMESPACE_URI, "InvalidRequest",
					"wst"),
					"The request was invalid or malformed (unsupported request type '"
							+ requestType + "')", new Exception());
		}

		OMElement usernameTokenElement = rstElement
				.getFirstChildWithName(new QName(WSSE_NAMESPACE_URI,
						"UsernameToken"));
		if (usernameTokenElement == null) {
			throw new AxisFault(
					new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
					"The request was invalid or malformed (missing UsernameToken element)",
					new Exception());
		}

		return usernameTokenElement;
	}

	private static String getURNOfFederatedSTS(OMElement rstElement)
			throws AxisFault {

		String delegateToURN = null;

		OMElement delegateToElement = rstElement
				.getFirstChildWithName(new QName(WST_NAMESPACE_URI,
						"DelegateTo"));
		if (delegateToElement != null) {
			// optional wst:DelegateTo is present
			OMElement endPointReferenceElement = delegateToElement
					.getFirstChildWithName(new QName(WSA_NAMESPACE_URI,
							"EndPointReference"));
			if (endPointReferenceElement == null) {
				throw new AxisFault(
						new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
						"The request was invalid or malformed (missing EndPointReference element within DelegateTo)",
						new Exception());
			}
			OMElement addressElement = endPointReferenceElement
					.getFirstChildWithName(new QName(WSA_NAMESPACE_URI,
							"Address"));
			if (addressElement == null) {
				throw new AxisFault(
						new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
						"The request was invalid or malformed (missing Address element within EndPointReference)",
						new Exception());
			}
			delegateToURN = addressElement.getText().trim();
		}

		return delegateToURN;
	}

	private static String getUsername(OMElement usernameTokenElement)
			throws AxisFault {
		OMElement usernameElement = usernameTokenElement
				.getFirstChildWithName(new QName(WSSE_NAMESPACE_URI, "Username"));
		if (usernameElement == null) {
			throw new AxisFault(
					new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
					"The request was invalid or malformed (missing Username element)",
					new Exception());
		}
		return usernameElement.getText().trim();
	}

	private static String getPassword(OMElement usernameTokenElement) {
		String password = null;
		OMElement passwordElement = usernameTokenElement
				.getFirstChildWithName(new QName(WSSE_NAMESPACE_URI, "Password"));
		if (passwordElement != null) {
			password = passwordElement.getText();
		}
		return password;
	}

	private void verifySignature() throws AxisFault {

		SOAPEnvelope soapEnvelope = MessageContext.getCurrentMessageContext()
				.getEnvelope();

		{ // Check presence of signature element in WS-Security element in
			// SOAP header
			// retrieve SOAP header
			SOAPHeader soapHeader = soapEnvelope.getHeader();
			if (soapHeader == null) {
				throw new AxisFault(
						new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
						"The request was invalid or malformed (missing SOAP header, mandatory when Password element is missing)",
						new Exception());
			}

			OMElement securityElement = soapHeader
					.getFirstChildWithName(new QName(WSSE_NAMESPACE_URI,
							"Security"));
			if (securityElement == null) {
				throw new AxisFault(
						new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
						"The request was invalid or malformed (missing Security element in SOAP header, mandatory when Password element is missing)",
						new Exception());
			}
			// retrieve the signature element
			OMElement signatureElement = securityElement
					.getFirstChildWithName(new QName(Constants.SignatureSpecNS,
							Constants._TAG_SIGNATURE));
			if (signatureElement == null) {
				throw new AxisFault(
						new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
						"The request was invalid or malformed (missing Signature element in Security element of SOAP header, mandatory when Password element is missing)",
						new Exception());
			}
		}
		// check signature
		try {

			Element envelopeElement = XMLUtils.toDOM(soapEnvelope);
			Element signatureElement = (Element) envelopeElement
					.getElementsByTagNameNS(Constants.SignatureSpecNS,
							Constants._TAG_SIGNATURE).item(0);

			if (!encryptionUtils.isRSTSignatureValid(signatureElement)) {
				throw new AxisFault(
						new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
						"The request was invalid or malformed (invalid RST signature)",
						new Exception());
			}
		} catch (AxisFault e) {
			throw e;
		} catch (XMLSignatureException e) {
			e.printStackTrace();
			throw new AxisFault(
					new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
					"The request was invalid or malformed (error in signature verification)",
					new Exception());
		} catch (XMLSecurityException e) {
			e.printStackTrace();
			throw new AxisFault(
					new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
					"The request was invalid or malformed (error in signature verification)",
					new Exception());
		} catch (Exception e) {
			e.printStackTrace();
			throw new AxisFault(
					new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
					"The request was invalid or malformed (error in signature verification)",
					new Exception());
		}
	}

	private OMElement buildSOAPFault(AxisFault axisFault) {
		return buildSOAPFault(axisFault.getFaultCode().getLocalPart(),
				axisFault.getReason());
	}
	
	private String getAppliesToValue(OMElement rstElement) throws AxisFault{
		String appliesToValue = "";
		OMElement appliesToElement = rstElement.getFirstChildWithName(new QName(WSP_NAMESPACE_URI, "AppliesTo"));
		if (appliesToElement != null) {
			// optional wst:AppliesTo is present
			logger.debug("AppliesTo is present");
			OMElement endPointReferenceElement = appliesToElement
					.getFirstChildWithName(new QName(WSA_NAMESPACE_URI,
							"EndPointReference"));
			if (endPointReferenceElement == null) {
				throw new AxisFault(
						new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
						"The request was invalid or malformed (missing EndPointReference element within AppliesTo)",
						new Exception());
			}
			OMElement addressElement = endPointReferenceElement
					.getFirstChildWithName(new QName(WSA_NAMESPACE_URI,
							"Address"));
			if (addressElement == null) {
				throw new AxisFault(
						new QName(WST_NAMESPACE_URI, "InvalidRequest", "wst"),
						"The request was invalid or malformed (missing Address element within AppliesTo/EndPointReference)",
						new Exception());
			}
			appliesToValue = addressElement.getText().trim();
		}else{
			//AppliesTo is absent
			return null;
		}
		return appliesToValue;
	}

	private OMElement buildSOAPFault(String faultCode, String faultReason) {

		SOAPFaultCode soapFaultCode = soapFactory.createSOAPFaultCode();
		soapFaultCode.setText(new QName(WST_NAMESPACE_URI, faultCode, "wst"));

		SOAPFaultReason soapFaultReason = soapFactory.createSOAPFaultReason();
		soapFaultReason.setText(faultReason);

		SOAPFault soapFault = soapFactory.createSOAPFault();
		soapFault.setCode(soapFaultCode);
		soapFault.setReason(soapFaultReason);
		
		if(logger.isDebugEnabled()) {
			logger.debug("Returned SOAP Fault = " + soapFault.toString());	
		}
		return soapFault;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see be.spacebel.webservice.authentication.AuthenticationService#
	 *      RequestSecurityToken(OMElement)
	 */
	public OMElement RequestSecurityToken(OMElement rstElement) {

		if(logger.isDebugEnabled()){
			logger.debug("Enter RequestSecurityToken with rstElement = " + rstElement.toString());	
		}
		
		String username = "?";
		String appliesToURI = "";
		try {
			/**
			 * Get AppliesTo value
			 */
			appliesToURI = getAppliesToValue(rstElement);
			logger.debug("AppliesTo URI = " + appliesToURI);

			
			Element samlAssertion = null;

			// flags indicating whether the SAML token shall be signed and/or
			// encrypted
			// these are set to false only if the STS is accessed as a federated
			// STS or, for encryption, if SAML_TOKEN_ENCRYPTION_ACTIVE property
			// parameter is set to false
			Boolean mustSign = true;
			Boolean mustEncrypt = isEncryptionActive;
			OMElement usernameTokenElement = getUsernameToken(rstElement);
			username = getUsername(usernameTokenElement);
			String password = getPassword(usernameTokenElement);
			String urnOfFederatedSTS = getURNOfFederatedSTS(rstElement);

			if (urnOfFederatedSTS != null) {
				// the optional DelegateTo element is present in the RST
				// this means that the STS is accessed either as a federating
				// or as a federated STS
				logger.debug("urnOfFederatedSTS" + urnOfFederatedSTS);
				if (urnOfFederatedSTS.equals(localSTSURN)) {
					// the STS is accessed as a federated STS
					// the returned SAML token is neither signed nor encrypted
					logger.info("delegated request is for the current STS");
					mustSign = false;
					mustEncrypt = false;
				} else {
					logger.info("delegated request is not for the current STS");
					// the STS is accessed as a federating STS
					// retrieve the URL of federated STS from the DelegateTo URN
					// address
					String urlOfFederatedSTS = ConfigurationUtils
							.getURLOfFederatedSTS(urnOfFederatedSTS);
					// relay the RST to the federated STS, which shall perform
					// checking and preparation of SAML assertion (unsigned and
					// in clear) ; if this RST fails, including by SOAP fault,
					// then an exception is thrown, which causes the present RST
					// to fail also
					samlAssertion = rstUtils.submitRSTNew(urlOfFederatedSTS,
							rstElement);
					//set Issuer to the  value of the delegating STS
					String issuerString = ConfigurationUtils.getProperty("SAML_ASSERTION_ISSUER");
					samlAssertion.getAttributes().getNamedItem("Issuer").setNodeValue(issuerString);
				}
			}

			if (samlAssertion == null) {
				// the STS is not accessed as a federating STS:
				// it performs by itself checking of RST and preparation of SAML
				// assertion from local user registry
				
				Attributes ldapAttributes = null;
				if (password == null) {
					// RST with signature
					// verify the signature and get its profile
					verifySignature();
					ldapAttributes = ldapAccess.getLdapAttributes(username);
				} else {
					// RST with password
					// authenticate the user and get its profile
					ldapAttributes = ldapAccess
							.authenticate(username, password);
				}
				// authentication successful : build a SAML assertion
				Attributes samlAttributes = samlTokenUtils
						.getSAMLAttributes(ldapAttributes);
				samlAssertion = samlTokenUtils.buildSAMLToken(samlAttributes);
				
			}
			
			if(logger.isDebugEnabled() && samlAssertion!=null){
				logger.debug("SAML token unencrypted = " + XMLUtils.toOM(samlAssertion).toString());
			}
			
			// SAML assertion element is ready, sign this assertion.
			Document contextDoc = db.newDocument();
			Node samlTokenNode = contextDoc.importNode(samlAssertion, true);
			logger.debug("import node with success");
			contextDoc.appendChild(samlTokenNode);
			if (mustSign) {
				logger.debug("begin signing the Element");
				encryptionUtils
						.signElement(contextDoc, (Element) samlTokenNode);
				logger.debug("end signing the Element");
			}

			// put the encrypted token in a RSTR
			OMFactory fac = OMAbstractFactory.getOMFactory();
			OMNamespace omNs = fac.createOMNamespace(WST_NAMESPACE_URI, "wst");
			OMElement rstrElement = fac.createOMElement(
					"RequestSecurityTokenResponse", omNs);

			OMElement tokenTypeElement = fac.createOMElement("TokenType", omNs);
			tokenTypeElement
					.addChild(fac
							.createOMText(tokenTypeElement,
									"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1"));
			rstrElement.addChild(tokenTypeElement);
			OMElement requestedSecurityTokenElement = fac.createOMElement(
					"RequestedSecurityToken", omNs);

			// definition of SAML token element
			OMElement samlTokenElement;
			if (addNonStandardAssertionElement) {
				// SAML Token is non-standard Assertion element on top of
				// EncryptedData element (OGC 07-118 0.0.4 and before)
				Element nonStandardAssertionElement = contextDoc
						.createElementNS(
								ConfigurationUtils.ASSERTION_NODE_NAMESPACE,
								ConfigurationUtils.ASSERTION_NODE_NAME);
				nonStandardAssertionElement.appendChild(samlTokenNode);

				if (mustEncrypt) {
					encryptionUtils.cipherElement(appliesToURI, contextDoc,
								nonStandardAssertionElement, true);
				}
				samlTokenElement = XMLUtils.toOM(nonStandardAssertionElement);

			} else {
				// SAML Token is EncryptedData element (default, from OGC 07-118
				// 0.0.5)
				// SAML token is ready, cipher the token.
				if(logger.isDebugEnabled()){
					logger.debug(XMLUtils.toOM(contextDoc.getDocumentElement()).toString());
				}
				if (mustEncrypt) {
					encryptionUtils.cipherElement(appliesToURI, contextDoc,
							(Element) samlTokenNode, false);
				}
				samlTokenElement = XMLUtils.toOM(contextDoc
						.getDocumentElement());
			}

			// put SAML token in the RequestedSecurityToken element of RSTR
			requestedSecurityTokenElement.addChild(samlTokenElement);

			rstrElement.addChild(requestedSecurityTokenElement);
			
			if(logger.isDebugEnabled()) {
				logger.debug("Enter RequestSecurityToken with rstElement = " + rstElement.toString());
			}

			return rstrElement;

		} catch (AxisFault e) {
			// propagate AxisFault exception
			logger.error("AxisFault catched, detail : " + e.getMessage());
			e.printStackTrace();
			return buildSOAPFault(e);

		} catch (AuthenticationException e1) {
			// authentication failed
			e1.printStackTrace();
			return buildSOAPFault("FailedAuthentication",
					"Authentication failed");

		} catch (SAMLException e2) {
			logger.error("SAML error when authenticating user '" + username
					+ "', details: " + e2.getMessage());
			e2.printStackTrace();
			return buildSOAPFault("RequestFailed",
					"The specified request failed");
		} catch (Exception ex) {
			logger.error("error when authenticating user '" + username
					+ "', details: " + ex.getMessage());
			ex.printStackTrace();
			return buildSOAPFault("RequestFailed",
					"The specified request failed. " + ex.getMessage());
		}
	}
}
