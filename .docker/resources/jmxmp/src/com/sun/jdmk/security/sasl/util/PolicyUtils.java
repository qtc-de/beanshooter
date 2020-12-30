/*
 * @(#)file      PolicyUtils.java
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

package com.sun.jdmk.security.sasl.util;

import java.util.Map;
import javax.security.sasl.Sasl;

/**
 * Static class that contains utilities for dealing with Java SASL
 * security policy-related properties.
 */
public final class PolicyUtils {
    // Can't create one of these
    private PolicyUtils() {
    }

    public final static int NOPLAINTEXT = 0x0001;
    public final static int NOACTIVE = 0x0002;
    public final static int NODICTIONARY = 0x0004;
    public final static int FORWARD_SECRECY = 0x0008;
    public final static int NOANONYMOUS = 0x0010;
    public final static int PASS_CREDENTIALS = 0x0200;

    /**
     * Determines whether a mechanism's characteristics, as defined in flags,
     * fits the security policy properties found in props.
     * @param flags The mechanism's security characteristics
     * @param props The security policy properties to check
     * @return true if passes; false if fails
     */
    public static boolean checkPolicy(int flags, Map props) {
	if (props == null) {
	    return true;
	}

	if ("true".equalsIgnoreCase((String)props.get(Sasl.POLICY_NOPLAINTEXT))
	    && (flags&NOPLAINTEXT) == 0) {
	    return false;
	}
	if ("true".equalsIgnoreCase((String)props.get(Sasl.POLICY_NOACTIVE))
	    && (flags&NOACTIVE) == 0) {
	    return false;
	}
	if ("true".equalsIgnoreCase((String)props.get(Sasl.POLICY_NODICTIONARY))
	    && (flags&NODICTIONARY) == 0) {
	    return false;
	}
	if ("true".equalsIgnoreCase((String)props.get(Sasl.POLICY_NOANONYMOUS))
	    && (flags&NOANONYMOUS) == 0) {
	    return false;
	}
	if ("true".equalsIgnoreCase((String)props.get(Sasl.POLICY_FORWARD_SECRECY))
	    && (flags&FORWARD_SECRECY) == 0) {
	    return false;
	}
	if ("true".equalsIgnoreCase((String)props.get(Sasl.POLICY_PASS_CREDENTIALS))
	    && (flags&PASS_CREDENTIALS) == 0) {
	    return false;
	}

	return true;
    }

    /**
     * Given a list of mechanisms and their characteristics, select the
     * subset that conforms to the policies defined in props.
     * Useful for SaslXXXFactory.getMechanismNames(props) implementations.
     *
     */
    public static String[] filterMechs(String[] mechs, int[] policies, 
	Map props) {
	if (props == null) {
	    return (String[])mechs.clone();
	}

	boolean[] passed = new boolean[mechs.length];
	int count = 0;
	for (int i = 0; i< mechs.length; i++) {
	    if (passed[i] = checkPolicy(policies[i], props)) {
		++count;
	    }
	}
	String[] answer = new String[count];
	for (int i = 0, j=0; i< mechs.length; i++) {
	    if (passed[i]) {
		answer[j++] = mechs[i];
	    }
	}

	return answer;
    }
}
