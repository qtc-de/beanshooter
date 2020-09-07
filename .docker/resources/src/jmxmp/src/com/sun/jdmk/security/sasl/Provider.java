/*
 * @(#)file      Provider.java
 * @(#)author    Sun Microsystems, Inc.
 * @(#)version   1.4
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

import java.security.AccessController;
import java.security.PrivilegedAction;

/**
 * The Java DMK SASL provider.
 * <p>
 * Provides server support for PLAIN, i.e. implements the PLAIN SASL server
 * mechanism. (<A HREF="http://ftp.isi.edu/in-notes/rfc2595.txt">RFC 2595</A>)
 * <p>
 * Requires the following callbacks to be satisfied by the callback handler
 * when using PLAIN:
 * <ul>
 *   <li>{@link com.sun.jdmk.security.sasl.AuthenticateCallback}: to verify the
 *       authentication identity and password with the system authentication
 *       database.</li>
 *   <li>{@link javax.security.sasl.AuthorizeCallback}: to verify that the
 *       authentication credentials permit the client to log in as the
 *       authorization identity.</li>
 * </ul>
 */
public final class Provider extends java.security.Provider {

    private static final long serialVersionUID = 4578222529928792392L;

    private static final String info =
        "Java DMK SASL provider (implements server mechanisms for: PLAIN)";

    @SuppressWarnings({ "deprecation", "unchecked" })
	public Provider() {
        super("JavaDMKSASL", 5.1, info);
        AccessController.doPrivileged(new PrivilegedAction() {
                public Object run() {
                    // Server mechanisms
		    //
                    put("SaslServerFactory.PLAIN",
                        "com.sun.jdmk.security.sasl.plain.ServerFactoryImpl");
                    return null;
                }
            });
    }
}
