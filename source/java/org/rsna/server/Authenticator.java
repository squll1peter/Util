/*---------------------------------------------------------------
*  Copyright 2015 by the Radiological Society of North America
*
*  This source software is released under the terms of the
*  RSNA Public License (http://mirc.rsna.org/rsnapubliclicense.pdf)
*----------------------------------------------------------------*/

package org.rsna.server;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.Hashtable;
import java.security.SecureRandom;
import org.apache.log4j.Logger;
import org.rsna.util.Base64;
import org.rsna.util.FileUtil;

/**
 * The standard authenticator singleton class for the server.
 */
public class Authenticator {

	static final Logger logger = Logger.getLogger(Authenticator.class);

	static Authenticator authenticator = null;

	protected Hashtable<String,Session> sessions = null;
	protected Hashtable<String,String> csrfTokens = null;
	long timeout = 1 * 60 * 60 * 1000; //default session timeout in ms = 1 hour
	String sessionCookieName = "RSNASESSION";
	private static final boolean RSNA_HEADER_ENABLED =
		Boolean.parseBoolean(System.getProperty("org.rsna.auth.rsnaHeader.enabled", "false"));
	private static final SecureRandom CSRF_RANDOM = new SecureRandom();

	/**
	 * The protected constructor to prevent instantiation of
	 * the class except through the getInstance() method.
	 */
	protected Authenticator() {
		sessions = new Hashtable<String,Session>();
		csrfTokens = new Hashtable<String,String>();
	}

	/**
	 * Get the Authenticator instance, creating it if it does not exist.
	 * @return the current instance of the Authenticator, or a new instance
	 * if no current instance exists.
	 */
	public static synchronized Authenticator getInstance() {
		if (authenticator == null) authenticator = new Authenticator();
		return authenticator;
	}

	/**
	 * Set the Session cookie name.
	 * @param sessionCookieName the name of the session cookie
	 */
	public synchronized void setSessionCookieName(String sessionCookieName) {
		this.sessionCookieName = sessionCookieName;
	}

	/**
	 * Set the Session timeout.
	 * @param timeout the timeout in milliseconds
	 */
	public synchronized void setSessionTimeout(long timeout) {
		this.timeout = timeout;
	}

	/**
	 * Get the Session timeout.
	 * @return the current timeout
	 */
	public synchronized long getSessionTimeout() {
		return timeout;
	}

	/**
	 * Get the number of active sessions.
	 * @return the number of sessions in the sessions table
	 */
	public synchronized int getActiveSessionCount() {
		return sessions.size();
	}

	/**
	 * Authenticate the user from an HttpRequest.
	 * @param req the request.
	 * @return the authenticated user, or null if the user cannot be authenticated.
	 */
    public User authenticate(HttpRequest req) {
		Session session;
		Users users = Users.getInstance();

		//First, check for an SSO session cookie
		if (users.supportsSSO()) {
			String ssoCookieName = users.getSSOCookieName();
			String id = req.getCookie(ssoCookieName);
			logger.debug("Authenticating "+id);
			if (id != null) {
				if ( ((session=sessions.get(id)) != null) && session.appliesTo(req) ) {
					logger.debug("...existing session matched");
					session.recordAccess();
					return session.user;
				}
				else {
					logger.debug("...no existing session; validating the request");
					User user = users.validate(req);
					if (user != null) {
						try {
							session = new Session(user, req.getRemoteAddress());
							//Note: we don't use the id created by the session
							//because the SSO system has already set the cookie,
							//so we index on that.
							sessions.put(id, session);
							logger.debug("...created session for "+session.user.getUsername());
							session.recordAccess();
							return session.user;
						}
						catch (Exception unable) {
							logger.debug("Unable to create the session", unable);
						}
					}
					logger.debug("...request did not validate");
				}
			}
		}

		//No joy, try the session cookie
		String id = req.getCookie(sessionCookieName);
		if ( (id != null) && ((session=sessions.get(id)) != null) && session.appliesTo(req) ) {
			session.recordAccess();
			return session.user;
		}

		//No session cookie, or cookie is not valid; check the headers.
		//First try the Authorization header.
		String credentials = req.getHeader("Authorization");
		if ((credentials != null) && isSecure(req)) {
			String type = "basic";
			credentials = credentials.trim();
			if (credentials.toLowerCase().startsWith(type)) {
				credentials = credentials.substring(type.length()).trim();
				try {
					credentials = new String(Base64.decode(credentials), "UTF-8");
					User user = getUserFromCredentials(credentials, req);
					if (user != null) return user;
				}
				catch (Exception ex) { }
			}
		}
		else if (credentials != null) {
			logger.debug("Rejected Basic auth over non-HTTPS request from "+req.getRemoteAddress());
		}

		//Next try the RSNA header. This header is not encoded.
		if (RSNA_HEADER_ENABLED) {
			credentials = req.getHeader("RSNA");
			if (credentials != null) {
				User user = getUserFromCredentials(credentials, req);
				if (user != null) return user;
			}
		}

		//The user cannot be authenticated.
		return null;
	}

	private User getUserFromCredentials(String credentials, HttpRequest req) {
		Users users = Users.getInstance();
		String[] up = credentials.split(":");
		User user = null;
		if (up.length == 2) {
			user = users.authenticate(up[0], up[1], req);
		}
		else if (up.length == 1) {
			user = users.authenticate(up[0], "", req);
		}
		return user;
	}

	/**
	 * Get the username for a session identified by a session ID.
	 * @param id the ID of the session.
	 * @return the username of the session owner, or null if the
	 * session does not exist.
	 */
    public String getUsernameForSession(String id) {
		if (id != null) {
			Session session = sessions.get(id);
			if (session != null) return session.user.getUsername();
		}
		return null;
	}

	/**
	 * Create a session for a User, storing the session
	 * cookie in the supplied HttpResponse as a Set-Cookie
	 * header.
	 * @param user the user for whom to create a session.
	 * @param req the response.
	 * @param res the response.
	 * @return true if the session was created; false otherwise.
	 */
    public boolean createSession(User user, HttpRequest req, HttpResponse res) {
		try {
			Session session = new Session(user, req.getRemoteAddress());
			sessions.put(session.id, session);
			csrfTokens.put(session.id, createCsrfToken());
			if (!Users.getInstance().supportsSSO()) {
				res.setHeader("Set-Cookie", getSessionCookieValue(req, session.id, false));
				res.setHeader("Cache-Control", "no-cache=\"set-cookie\"");
			}
			return true;
		}
		catch (Exception failed) {
			return false;
		}
	}

	/**
	 * Close a session if one is identified by a session
	 * cookie in the request. Closing a session deletes the
	 * session from the sessions hashtable, making the session
	 * unrecognizable by the authenticator. It also sets
	 * a dummy session cookie with Max-Age=0.
	 * @param req the request.
	 * @param res the response.
	 */
    public void closeSession(HttpRequest req, HttpResponse res) {
		Users users = Users.getInstance();

		//Get the session cookie name
		String name = users.getSSOCookieName();
		if (name.equals("")) name = sessionCookieName;

		//See if there is a cookie specifying an existing session.
		String id = req.getCookie(name);
		if (id != null) {
			//A session was specified. Remove it from the hashtable.
			sessions.remove(id);
			csrfTokens.remove(id);
			if (!users.supportsSSO()) {
				//Set a dummy session cookie that expires immediately.
				res.setHeader("Set-Cookie", getSessionCookieValue(req, "NONE", true));
				res.setHeader("Cache-Control", "no-cache=\"set-cookie\"");
			}
		}
	}

	private boolean isSecure(HttpRequest req) {
		String protocol = req.getProtocol();
		return (protocol != null) && protocol.equalsIgnoreCase("https");
	}

	private String getSessionCookieValue(HttpRequest req, String sessionValue, boolean expireNow) {
		StringBuffer sb = new StringBuffer();
		sb.append(sessionCookieName).append("=").append(sessionValue);
		sb.append("; Path=/");
		sb.append("; HttpOnly");
		sb.append("; SameSite=Lax");
		if (isSecure(req)) sb.append("; Secure");
		if (expireNow) sb.append("; Max-Age=0");
		return sb.toString();
	}
	
	/**
	 * Remove all sessions that have timed out.
	 */
	public void removeInactiveSessions() {
		for (String id : sessions.keySet().toArray(new String[sessions.size()])) {
			Session session = sessions.get(id);
			if (session.hasTimedOut()) {
				sessions.remove(id);
				csrfTokens.remove(id);
			}
		}
	}

	public synchronized String getCsrfToken(HttpRequest req) {
		if (req == null) return "";
		String sessionId = req.getCookie(sessionCookieName);
		if (sessionId == null) return "";
		String token = csrfTokens.get(sessionId);
		if (token == null) {
			token = createCsrfToken();
			csrfTokens.put(sessionId, token);
		}
		return token;
	}

	public synchronized boolean validateCsrfToken(HttpRequest req) {
		if (req == null) return false;
		String sessionId = req.getCookie(sessionCookieName);
		if (sessionId == null) return false;
		String expected = csrfTokens.get(sessionId);
		if (expected == null) return false;
		String provided = req.getParameter("csrfToken", "").trim();
		if (provided.equals("")) provided = req.getHeader("X-CSRF-Token", "").trim();
		return constantTimeEquals(expected, provided);
	}

	private String createCsrfToken() {
		byte[] bytes = new byte[24];
		CSRF_RANDOM.nextBytes(bytes);
		return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
	}

	private boolean constantTimeEquals(String a, String b) {
		if ((a == null) || (b == null)) return false;
		byte[] ab = a.getBytes();
		byte[] bb = b.getBytes();
		if (ab.length != bb.length) return false;
		int result = 0;
		for (int i=0; i<ab.length; i++) result |= (ab[i] ^ bb[i]);
		return result == 0;
	}
	
	/**
	 * GetActiveUsers.
	 * @return the array of active Sessions (after removing inactive Sessions from the sessions table).
	 */
	public Session[] getActiveSessions() {
		removeInactiveSessions();
		Session[] s = new Session[sessions.size()];
		s = sessions.values().toArray(s);
		Arrays.sort(s);
		return s;
	}

}
