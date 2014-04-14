package be.spacebel.webservice.authentication;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.Iterator;

import javax.xml.soap.MessageFactory;
import javax.xml.soap.MimeHeaders;
import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;


import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.util.XMLUtils;
import org.apache.log4j.Logger;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

public class RSTUtils {

	private ServiceClient _sender = null; 
	private Logger logger = Logger.getLogger(this.getClass().getName());
	
	private static final String WST_NAMESPACE_URI = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/";

	/**
	 * Invoke a webservice synchronous
	 * 
	 * @param destination
	 *            Endpoint of the webservice
	 * @param message
	 *            SOAPMessage that will be transfered
	 * @return
	 * @throws SOAPException
	 * @throws IOException
	 * @throws WebServiceException
	 */
	private static SOAPMessage callSyncService(String destination,
			SOAPMessage message) throws SOAPException, IOException,
			WebServiceException {

		// First create the connection
		SOAPConnectionFactory soapConnFactory = SOAPConnectionFactory
				.newInstance();
		SOAPConnection connection = soapConnFactory.createConnection();

		// Send the message
		SOAPMessage reply = connection.call(message, destination);

		// Close the connection
		connection.close();
		if (reply.getSOAPBody() != null
				&& reply.getSOAPBody().getFault() != null) {
			SOAPFault fault = reply.getSOAPBody().getFault();
			String faultCode = fault.getFaultCode() == null ? "" : fault
					.getFaultCode();
			String faultString = fault.getFaultString() == null ? "" : fault
					.getFaultString();
			String faultDetail = fault.getDetail() == null ? "" : fault
					.getDetail().toString();

			throw new WebServiceException(faultCode, faultString, faultDetail);
		}

		return reply;
	}

	/**
	 * Submit a RST towards a federated STS, extract and return SAML Assertion in clear 
	 * 
	 * @param urlOfFederatedSTS
	 *            End point of the federated STS Web service
	 * @param rstElement
	 *            RST SOAP Message that will be transfered
	 * @return Element
	 * @throws Exception
	 */
	public Element submitRST(String urlOfFederatedSTS, OMElement rstElement)
			throws Exception {

		// Create new SOAP message
//		MessageFactory messageFactory = MessageFactory.newInstance();
//		SOAPMessage soapMessage = messageFactory.createMessage();

		// Create objects for the message parts
//		SOAPPart soapPart = soapMessage.getSOAPPart();
//		SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
//		SOAPBody soapBody = soapEnvelope.getBody();
//		soapBody.appendChild(XMLUtils.toDOM(rstElement));
		
		logger.debug("RSTElement = " + rstElement.toString());
		if (_sender == null ) _sender = new ServiceClient();
		
		MessageContext inMesasgeContext = MessageContext.getCurrentMessageContext();
		
		Options options = inMesasgeContext.getOptions();
		options.setTo(new EndpointReference(urlOfFederatedSTS));
		_sender.setOptions(options);
		
		SOAPHeader soapHeader = inMesasgeContext.getEnvelope().getHeader();
		if (soapHeader != null) {
			logger.debug("enter copy soap header ");
			Iterator iter = soapHeader.getChildElements();
			while(iter.hasNext()){
				logger.debug("adding header items");
				_sender.addHeader((OMElement)iter.next());
			}
		}
		logger.debug("calling destination...");

		OMElement result = _sender.sendReceive(rstElement);
		
		Node assertionNode = XMLUtils.toDOM(result).getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Assertion").item(0);
		
		assertionNode.getAttributes().getNamedItem("Issuer").setNodeValue(ConfigurationUtils.getProperty("SAML_ASSERTION_ISSUER"));
		
		StringWriter strResult = new StringWriter();
		XMLUtils.toOM((Element)assertionNode).serialize(strResult);
		logger.debug("Federated STS response:" + strResult);

		if(assertionNode == null)logger.debug("Assertion Node is null");
		
		return (Element) assertionNode;
		

	}
	
	public Element submitRSTNew(String urlOfFederatedSTS, OMElement rstElement)
	throws Exception {

		logger.debug("RSTElement submitted to delegated STS is " + rstElement.toString());
		
		logger.debug("RSTElement submitted to delegated STS is " + rstElement.toString());
		
		if (_sender == null ) _sender = new ServiceClient();
		String xml = MessageContext.getCurrentMessageContext().getEnvelope().toStringWithConsume();
		MessageFactory factory = MessageFactory.newInstance();
		SOAPMessage soapMsg = factory.createMessage(new MimeHeaders(),
					new ByteArrayInputStream(xml.getBytes(Charset.forName("UTF-8"))));
		SOAPConnectionFactory soapConnFactory = SOAPConnectionFactory.newInstance();
		SOAPConnection connection = soapConnFactory.createConnection();
		SOAPMessage reply = connection.call(soapMsg, urlOfFederatedSTS);
		// Close the connection
		connection.close();
		
		Node assertionNode = reply.getSOAPPart().getDocumentElement().getElementsByTagNameNS("urn:oasis:names:tc:SAML:1.0:assertion", "Assertion").item(0);
		
		logger.debug("Federated STS response:" + assertionNode.toString());
		
		//if(assertionNode == null)log("Assertion Node is null");
		
		return (Element) assertionNode;
	}	
}
