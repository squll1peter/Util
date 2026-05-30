/*---------------------------------------------------------------
 *  Copyright 2015 by the Radiological Society of North America
 *
 *  This source software is released under the terms of the
 *  RSNA Public License (http://mirc.rsna.org/rsnapubliclicense.pdf)
 *----------------------------------------------------------------*/

package org.rsna.server;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Class to encapsulate a session.
 */
public class Session implements Comparable<Session> {
	private static final SecureRandom SECURE_RANDOM = new SecureRandom();
	private static final int SESSION_ID_BYTES = 24; //192 bits
	public long lastAccess;
	public final User user;
	public final String ipAddress;
	public final String id;

	//Construct a Session
	public Session(User user, String ipAddress) throws Exception {
		lastAccess = System.currentTimeMillis();
		this.user = user;
		this.ipAddress = ipAddress;
		id = getSessionID();
	}
	
	public User getUser() {
		return user;
	}

	public boolean appliesTo(HttpRequest req) {
		long timeout = Authenticator.getInstance().getSessionTimeout();
		boolean ok = req.getRemoteAddress().equals(ipAddress);
		if (ok && (timeout > 0)) {
			ok &= ((System.currentTimeMillis() - lastAccess) < timeout);
		}
		return ok;
	}
	
	public boolean hasTimedOut() {
		long timeout = Authenticator.getInstance().getSessionTimeout();
		return (timeout > 0) && ((System.currentTimeMillis() - lastAccess) >= timeout);
	}

	public void recordAccess() {
		lastAccess = System.currentTimeMillis();
	}
	
	public int compareTo(Session s) {
		long dif = lastAccess - s.lastAccess;
		return (dif>0) ? 1 : ((dif==0) ? 0 : -1);
	}

	//Make a session ID using cryptographically strong random bytes.
	private String getSessionID() {
		byte[] bytes = new byte[SESSION_ID_BYTES];
		SECURE_RANDOM.nextBytes(bytes);
		return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}
}
