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

import org.apache.axiom.om.OMElement;

/**
 * The AuthenticationService interface defines the signatures of all the
 * operations provided by authentication service; it is used to publish these
 * operations as a web service.
 * 
 * @author Pierre Denis (pds)
 * 
 */
public interface AuthenticationService {

	/**
	 * Checks the matching of the given user id and password in the user
	 * registry; if a matching user is found, then an encrypted SAML token with
	 * user's attributes is returned; otherwise (authentication failure), the
	 * exception report is returned to indicate the error's root cause.
	 * 
	 * @param userId
	 *            user identification
	 * @param password
	 *            user password
	 * 
	 * @return DOM element containing the SAML token if authentication succeeds,
	 *         null otherwise
	 */
	

	public abstract OMElement RequestSecurityToken(OMElement soapMsg) throws Exception;
	

}