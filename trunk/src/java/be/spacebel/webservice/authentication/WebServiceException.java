/*	$Id$
 *  Copyright (c) 2009 Spacebel S.A.
 *  I. Vandammestraat 5-7, 1560 Hoeilaart, Belgium
 *  All rights reserved.
 *
 */
package be.spacebel.webservice.authentication;

/**
 * The WebServiceException class defines a custom web service exception
 * 
 * @author Minh Nguyen Quang (mng)
 * 
 */
public class WebServiceException extends Exception{	
	private static final long serialVersionUID = 3393006394769150030L;
	
	private String faultCode;
	private String detail;
	
	public WebServiceException(String faultCode, String faultString, String detail) {
		super(faultString);
		this.faultCode = faultCode;
		this.detail = detail;
	}
	
	public WebServiceException(String faultCode, String faultString) {
		super(faultString);
		this.faultCode = faultCode;
	}

	public String getFaultCode() {
		return faultCode;
	}

	public void setFaultCode(String faultCode) {
		this.faultCode = faultCode;
	}

	public String getDetail() {
		return detail;
	}

	public void setDetail(String detail) {
		this.detail = detail;
	}
}
