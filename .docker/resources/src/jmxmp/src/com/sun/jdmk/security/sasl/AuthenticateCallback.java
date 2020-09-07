/*
 * @(#)file      AuthenticateCallback.java
 * @(#)author    Sun Microsystems, Inc.
 * @(#)version   1.3
 * @(#)date      07/10/01
 *
 * 
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
 * 
 * Copyright (c) 2007 Sun Microsystems, Inc. All Rights Reserved.
 * 
 * The contents of this file are subject to the terms of either the GNU General
 * Public License Version 2 only ("GPL") or the Common Development and
 * Distribution License("CDDL")(collectively, the "License"). You may not use
 * this file except in compliance with the License. You can obtain a copy of the
 * License at http://opendmk.dev.java.net/legal_notices/licenses.txt or in the 
 * LEGAL_NOTICES folder that accompanied this code. See the License for the 
 * specific language governing permissions and limitations under the License.
 * 
 * When distributing the software, include this License Header Notice in each
 * file and include the License file found at
 *     http://opendmk.dev.java.net/legal_notices/licenses.txt
 * or in the LEGAL_NOTICES folder that accompanied this code.
 * Sun designates this particular file as subject to the "Classpath" exception
 * as provided by Sun in the GPL Version 2 section of the License file that
 * accompanied this code.
 * 
 * If applicable, add the following below the License Header, with the fields
 * enclosed by brackets [] replaced by your own identifying information:
 * 
 *       "Portions Copyrighted [year] [name of copyright owner]"
 * 
 * Contributor(s):
 * 
 * If you wish your version of this file to be governed by only the CDDL or
 * only the GPL Version 2, indicate your decision by adding
 * 
 *       "[Contributor] elects to include this software in this distribution
 *        under the [CDDL or GPL Version 2] license."
 * 
 * If you don't indicate a single choice of license, a recipient has the option
 * to distribute your version of this file under either the CDDL or the GPL
 * Version 2, or to extend the choice of license to its licensees as provided
 * above. However, if you add GPL Version 2 code and therefore, elected the
 * GPL Version 2 license, then the option applies only if the new code is made
 * subject to such option by the copyright holder.
 * 
 */

package com.sun.jdmk.security.sasl;

import java.io.Serializable;
import javax.security.auth.callback.Callback;

/**
 * This callback is used by {@link javax.security.sasl.SaslServer} to verify the
 * authentication identity and password with the system authentication database.
 */
public class AuthenticateCallback implements Callback, Serializable {

    private static final long serialVersionUID = -9067046894103379433L;

    /**
     * The authentication identity to check.
     * @serial
     */
    private String authenticationID;

    /**
     * The password to check.
     * @serial
     */
    private char[] password;

    /**
     * A flag indicating whether the authentication identity and password have
     * been successfully verified by the system authentication database.
     * @serial
     */
    private boolean authenticated;

    /**
     * Constructs an instance of <tt>AuthenticateCallback</tt>.
     *
     * @param authenticationID The authentication identity.
     * @param password The password. This method makes a copy of the input
     * <i>password</i> before storing it.
     */
    public AuthenticateCallback(String authenticationID, char[] password) {
        this.authenticationID = authenticationID;
        this.password = (password == null ? null : (char[])password.clone());
    }

    /**
     * Returns the authentication identity to check.
     * @return The authentication identity to check.
     */
    public String getAuthenticationID() {
        return authenticationID;
    }

    /**
     * Returns the password to check.
     * @return The password to check. This method returns a copy
     * of the retrieved password.
     */
    public char[] getPassword() {
        return (password == null ? null : (char[])password.clone());
    }

    /**
     * Determines whether the authentication identity and password have
     * been successfully verified by the system authentication database.
     *
     * @return <tt>true</tt> if authentication succeeded; <tt>false</tt>
     * otherwise.
     *
     * @see #setAuthenticated(boolean)
     */
    public boolean isAuthenticated() {
        return authenticated;
    }

    /**
     * Sets whether the authentication succeeded.
     * @param ok <tt>true</tt> if authentication succeeded; <tt>false</tt>
     * otherwise.
     *
     * @see #isAuthenticated()
     */
    public void setAuthenticated(boolean ok) {
        authenticated = ok;
    }

    /**
     * Clear the password to check.
     */
    public void clearPassword() {
        if (password != null) {
            for (int i = 0; i < password.length; i++) password[i] = ' ';
        }
    }
}
