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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.MissingResourceException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import org.apache.log4j.Logger;
import org.apache.xml.security.encryption.EncryptedData;
import org.apache.xml.security.encryption.EncryptedKey;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.signature.XMLSignatureException;
import org.apache.xml.security.transforms.Transforms;
import org.apache.xml.security.utils.Constants;
import org.apache.xml.security.utils.IdResolver;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * The EncryptionUtils class provides methods to sign and encrypt XML element
 * 
 * @author Pierre Denis (pds)
 * @author The Hoa Nguyen
 * 
 */
public class EncryptionUtils {

	private Logger logger = Logger.getLogger(this.getClass().getName());

	private KeyStore keystore;
	// authentication private key used to sign SAML token
	private PrivateKey authenticationPrivateKey;
	// authorisation public key used to cipher SAML token.
	private PublicKey authorisationPublicKey;
	// public key of client used to verify signature of RST without password
	private List<PublicKey> clientPublicKeys;

	private X509Certificate stsCertificate;
	
	private XMLCipher keyCipher;
	private XMLCipher tokenCipher;
	private KeyGenerator keyGenerator;

	private boolean oldSignatureFormat = false;

	//final static String SIGNED_ELEMENT_REFERENCE_URI = "SAML_TOKEN_SIGNATURE";

	/**
	 * Constructs a new instance of EncryptionUtils by initializing the members
	 * from configuration parameters
	 * 
	 * @throws KeyStoreException
	 * @throws XMLEncryptionException
	 * @throws NoSuchAlgorithmException
	 * @throws UnrecoverableEntryException
	 * @throws CertificateException
	 * @throws IOException
	 * 
	 */
	public EncryptionUtils() throws KeyStoreException, XMLEncryptionException,
			NoSuchAlgorithmException, UnrecoverableEntryException,
			CertificateException, IOException {

		super();

		clientPublicKeys = new ArrayList<PublicKey>();

		if (logger.isDebugEnabled()) {
			logger.debug("EncryptionUtils:: enter");
		}

		// initialize Apache XML security library
		org.apache.xml.security.Init.init();

		// retrieves keystore access parameters
		String keystoreLocation = ConfigurationUtils
				.getProperty("KEYSTORE_LOCATION");

		String keystorePassword = ConfigurationUtils
				.getProperty("KEYSTORE_PASSWORD");
		String authenticationCertificatePassword = ConfigurationUtils
				.getProperty("AUTHENTICATION_CERTIFICATE_PASSWORD");
		String authenticationCertificateAlias = ConfigurationUtils
				.getProperty("AUTHENTICATION_CERTIFICATE_ALIAS");
		String authorisationCertificateAlias = ConfigurationUtils
				.getProperty("AUTHORISATION_CERTIFICATE_ALIAS");
		String clientCertificateAliases = ConfigurationUtils
				.getProperty("CLIENT_CERTIFICATE_ALIASES");

		try {
			if ("true".equalsIgnoreCase(ConfigurationUtils
					.getProperty("SAML_OLD_SIGNATURE"))) {
				oldSignatureFormat = true;
			}
		} catch (MissingResourceException e) {
			// SAML_OLD_SIGNATURE missing in the configuration
			// take default oldSignatureFormat=false
		}

		logger.info("KEYSTORE_LOCATION = " + keystoreLocation);
		logger.info("AUTHENTICATION_CERTIFICATE_ALIAS = "
				+ authenticationCertificateAlias);
		logger.info("CLIENT_CERTIFICATE_ALIASES = " + clientCertificateAliases);
		logger.info("SAML old signature format : " + oldSignatureFormat);

		// get local JKS keystore
		keystore = KeyStore.getInstance("JKS");
		File keystoreFile = new File(keystoreLocation);

		if (keystoreFile.exists()) {
			FileInputStream input = new FileInputStream(keystoreFile);
			keystore.load(input, keystorePassword.toCharArray());
			input.close();
		} else {
			logger.error("Required keystore file "
					+ keystoreFile.getAbsolutePath() + " is missing");
		}

		// build and initialize generator of symmetrical keys
		keyGenerator = KeyGenerator.getInstance("AES");
		keyGenerator.init(128);

		// retrieve certificate and keys from the key store
		// retrieve authentication private key (used to sign SAML token)
		KeyStore.ProtectionParameter keystoreProtection = new KeyStore.PasswordProtection(
				authenticationCertificatePassword.toCharArray());

		KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) keystore
				.getEntry(authenticationCertificateAlias, keystoreProtection);

		stsCertificate = (X509Certificate) privateKeyEntry.getCertificate();
		
		authenticationPrivateKey = privateKeyEntry.getPrivateKey();

		// retrieve authorisation public key (used to encrypt SAML token)
		Certificate authorisationCertificate = keystore
				.getCertificate(authorisationCertificateAlias);
		authorisationPublicKey = authorisationCertificate.getPublicKey();

		// retrieve public keys of trusted clients (used to check signature of
		// RST)
		String[] splttedClientCertificateAliases = clientCertificateAliases
				.split(",");
		for (int i = 0; i < splttedClientCertificateAliases.length; i++) {
			String clientCertificateAlias = splttedClientCertificateAliases[i]
					.trim();
			logger.info("getting '" + clientCertificateAlias + "'");
			if (clientCertificateAlias.length() > 0) {
				try {
					Certificate clientCertificate = keystore
							.getCertificate(clientCertificateAlias);
					clientPublicKeys.add(clientCertificate.getPublicKey());
				} catch (Exception exception) {
					logger
							.error("Impossible to retrieve public key of certificate '"
									+ clientCertificateAlias
									+ "' in STS keystore");
				}
			}
		}

		// build the cipher used to encrypt the token
		// it uses symmetrical key algorithm AES 128
		tokenCipher = XMLCipher.getInstance(XMLCipher.AES_128);
		// build the cipher used to encrypt the symmetrical key
		// it uses asymmetrical key algorithm RSA
		keyCipher = XMLCipher.getInstance(XMLCipher.RSA_v1dot5);

		if (logger.isDebugEnabled()) {
			logger.debug("EncryptionUtils:: exit");
		}
	}

	/**
	 * Ciphers the given element in the given document, by using the public key
	 * present in the certificate of a target entity having the given alias; if
	 * the alias is null, then the local public key is used
	 * 
	 * @param targetCertificateAlias
	 *            alias of the certificate in the keystore to retrive the public
	 *            key of the target entity
	 * @param document
	 *            DOM document containing the element to be encrypted
	 * @param element
	 *            DOM element to be encrypted
	 * @param content
	 *            flag indicating whether the element itself has to be encrypted
	 *            (false) or its children have to be encrypted (true)
	 * 
	 * @throws Exception
	 *             if encryption fails
	 */
	public void cipherElement(String targetCertificateAlias, Document document,
			Element element, boolean content) throws Exception {

		logger.debug("Enter cipherElement");
		// generate the symmetrical key
		SecretKey symmetricalKey = keyGenerator.generateKey();

		// encryption of symmetrical key with public key
		PublicKey publicKey;
		if (targetCertificateAlias == null) {
			publicKey = authorisationPublicKey;
		} else {
			Certificate certificate = this.keystore
					.getCertificate(targetCertificateAlias);
			if (certificate == null) {
				String errorMsg = "Failed to retrieve the public key associated with the Relying Party identified by the AppliesTo URI " + targetCertificateAlias + " from the STS keystore to encrypt the SAML token";
				logger.error(errorMsg);
				throw new Exception(errorMsg);
			}
			publicKey = certificate.getPublicKey();
		}

		keyCipher.init(XMLCipher.WRAP_MODE, publicKey);
		EncryptedKey encryptedKey = keyCipher.encryptKey(document,
				symmetricalKey);

		// encryption of document with secret key
		tokenCipher.init(XMLCipher.ENCRYPT_MODE, symmetricalKey);
		EncryptedData encryptedData = tokenCipher.getEncryptedData();
		KeyInfo keyInfo = new KeyInfo(document);
		keyInfo.add(encryptedKey);
		encryptedData.setKeyInfo(keyInfo);

		tokenCipher.doFinal(document, element, content);
		logger.debug("Exit cipherElement");

	}

	/**
	 * Calculates and put a digital signature for the given element in the given
	 * document
	 * 
	 * @param document
	 *            DOM document containing the element to be signed
	 * @param element
	 *            DOM element to be signed
	 * @throws XMLSecurityException
	 *             if signature fails
	 */
	public void signElement(Document document, Element element)
			throws XMLSecurityException {

		try {
			// default, from OGC 07-118 0.0.6
			// - exclusive XML canonicalisation (this is
			// "http://www.w3.org/2001/10/xml-exc-c14n")
			// - URI reference to SAML Assertion element
			String canonicalisationAlgorithm = Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS;

			// builds a new signature
			XMLSignature xmlSignature = new XMLSignature(document, "",
					XMLSignature.ALGO_ID_SIGNATURE_RSA,canonicalisationAlgorithm);
			// and append it to the element to be signed
			element.appendChild(xmlSignature.getElement());

			// specify the signature protocol: enveloped signature, SHA-1 as
			// digest algorithm
			Transforms transforms = new Transforms(document);
			transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
			
			// put signature reference to Assertion's Id
			String assertionId = element.getAttribute("AssertionID");
			String referenceURI = "#" + assertionId;
			
			if (oldSignatureFormat) {
				// (OGC 07-118 0.0.5 and before:
				// - non-exclusive XML canonicalisation (this is
				// "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments")
				// - empty URI reference
				canonicalisationAlgorithm = Transforms.TRANSFORM_C14N_WITH_COMMENTS;
				referenceURI = "";
				// add the certificate in the signature, so that the receiver can
				// retrieve the public key and validate the signature
				xmlSignature.addKeyInfo(stsCertificate);
				
			}
			transforms.addTransform(canonicalisationAlgorithm);
			xmlSignature.addDocument(referenceURI, transforms,
					Constants.ALGO_ID_DIGEST_SHA1);

			// calculate and insert signature
			xmlSignature.sign(authenticationPrivateKey);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Validates whether the document has a valid signature
	 * 
	 * @param signatureElement
	 *            signature element
	 * @return true if and only if the signature is valid for the given document
	 * @throws XMLSecurityException
	 * @throws XMLSignatureException
	 */
	public boolean isRSTSignatureValid(Element signatureElement)
			throws XMLSignatureException, XMLSecurityException {
		if(logger.isDebugEnabled()){
			logger.debug("Enter EncryptionUtils::isRSTSignatureValid");
		}

		// build XML signature
		XMLSignature xmlSignature = new XMLSignature(signatureElement, "");
		int keyIndex = 0;
		for (PublicKey clientPublicKey : clientPublicKeys) {
			keyIndex++;
			if(logger.isDebugEnabled()){
				logger.debug("checking with clientPublicKey No. (the order of the key alias appeared in the CLIENT_CERTIFICATE_ALIASES)" + keyIndex);
			}
			try {
				if (xmlSignature.checkSignatureValue(clientPublicKey)) {
					// one of public key matches signature: RST client is trusted
					if(logger.isDebugEnabled()){
						logger.debug("Exit EncryptionUtils::isRSTSignatureValid with TRUE value, signature is valid");
					}
					return true;
				}
			} catch (Exception e) {
				logger.info("Key alias no. " + keyIndex + " is not valid, reason:" + e.getMessage());
			}
		}
		if(logger.isDebugEnabled()){
			logger.debug("Exit EncryptionUtils::isRSTSignatureValid with FALSE value, signature is INvalid");
		}
		// no public key is matching the signature: RST client is not trusted
		return false;
	}
}
