/*---------------------------------------------------------------
*  Copyright 2015 by the Radiological Society of North America
*
*  This source software is released under the terms of the
*  RSNA Public License (http://mirc.rsna.org/rsnapubliclicense.pdf)
*----------------------------------------------------------------*/

package org.rsna.servlets;

import java.io.File;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import org.apache.log4j.Logger;
import org.rsna.server.Authenticator;
import org.rsna.server.HttpRequest;
import org.rsna.server.HttpResponse;
import org.rsna.server.User;
import org.rsna.server.Users;
import org.rsna.server.UsersOpenAMImpl;
import org.rsna.util.AttackLog;
import org.rsna.util.FileUtil;
import org.rsna.util.StringUtil;

/**
 * The LoginServlet.
 */
public class LoginServlet extends Servlet {

	static final Logger logger = Logger.getLogger(LoginServlet.class);
	private static final int MAX_FAILURES = 5;
	private static final long FAILURE_WINDOW_MS = 5L * 60L * 1000L;
	private static final long RESET_INACTIVITY_MS = 15L * 60L * 1000L;
	private static final long MAX_DELAY_MS = 2000L;
	private static final int MAX_THROTTLE_STATES = 1000;
	private static final ConcurrentHashMap<String,ThrottleState> throttleStates = new ConcurrentHashMap<String,ThrottleState>();

	/**
	 * Construct a LoginServlet.
	 * @param root the root directory of the server.
	 * @param context the path identifying the servlet.
	 */
	public LoginServlet(File root, String context) {
		super(root, context);
	}

	/**
	 * The GET handler: display a page containing a form allowing
	 * the user to log in. The page is not actually stored in the
	 * root directory of the servlet. It is instead stored in the
	 * root directory of the program. This makes the file available
	 * for all server instances, even ones on other ports.
	 * <p>
	 * This method can also be used by Ajax applications to log in.
	 * The path must end in /ajax, and the username and password
	 * must be passed in the query string. This call returns a
	 * response code of either 200 if the login is successful or
	 * 403 if it fails. If the Ajax application wishes to log out,
	 * it must supply the /ajax path element and the logout query string.
	 * @param req the request object
	 * @param res the response object
	 */
	public void doGet(HttpRequest req, HttpResponse res) {

		logger.debug("Request received:\n"+req.toVerboseString());

 		//Get the possible query parameters.
		String username = req.getParameter("username");
		String password = req.getParameter("password");
		String logout = req.getParameter("logout");
		
		//See if this is an OpenAM login that requires authentication.
		Users users = Users.getInstance();
		if (!req.isFromAuthenticatedUser() 
				&& (users instanceof UsersOpenAMImpl)
				&& req.getServer().getServletSelector().getRequireAuthentication()) {
			
			String redirectURL = req.getProtocol()+"://"+req.getHost()+"/";
			String url = ((UsersOpenAMImpl)users).getLoginURL(redirectURL);
			res.redirect(url);
		}

		//See if this is an ajax call or a web page request
		else if (req.getPath().endsWith("/ajax")) {
			//It's an ajax call.
			if (logout == null) {
				if ((username != null) || (password != null)) {
					logger.warn("Rejected GET credential login request from "+req.getRemoteAddress());
					res.setResponseCode(403);
				}
				else {
					res.setResponseCode(403);
				}
				res.send();
			}
			else {
				Authenticator.getInstance().closeSession(req, res);
				res.send();
			}
		}
		else {
			//It's a web page request.
			if (logout == null) {

				//See if it's a direct login
				if ((username != null) && (password != null)) {
					logger.warn("Rejected GET credential login request from "+req.getRemoteAddress());
					Authenticator.getInstance().closeSession(req, res);
					redirect(req, res);
					return;
				}

				//No, see if we are to suppress the login if the
				//user is already authenticated and just go directly
				//to the requested URL (or the default):
				if (req.hasParameter("skip") && req.isFromAuthenticatedUser()) {
					redirect(req, res);
					return;
				}

				//No, display the login page
				String loginPage =
							FileUtil.getText(
								FileUtil.getStream( new File(root, "login.html"), "/login.html" ) );

				//Set the redirect URL for the post.
				Properties props = new Properties();
				String url = req.getParameter("url", "");
				if (isAttack(req, url)) url = "";
				props.put("url", url);
				loginPage = StringUtil.replace(loginPage, props);

				res.write(loginPage);
				res.disableCaching();
				res.setContentType("html");
				res.send();
			}
			else {
				Authenticator.getInstance().closeSession(req, res);
				redirect(req, res);
			}
		}
	}

	/**
	 * The POST handler: authenticate the user from the form parameters.
	 * @param req the request object
	 * @param res the response object
	 */
	public void doPost(HttpRequest req, HttpResponse res) {

		logger.debug("Request received:\n"+req.toVerboseString());

		String username = req.getParameter("username");
		String password = req.getParameter("password");
		ThrottleDecision decision = evaluateThrottle(req, username);
		if (decision.blocked) {
			sleep(decision.delayMs);
			AttackLog.getInstance().recordEvent(new AttackLog.SecurityEvent(
				System.currentTimeMillis(), req.getRemoteAddress(), req.getMethod(), req.getPath(), req.getHost(),
				"throttle event", "warn", "login throttled", username, req.getHeader("User-Agent", "")));
			res.setResponseCode(429);
			res.send();
			return;
		}
		boolean passed = login(req, res, username, password);
		if (!passed) {
			decision = registerFailure(req, username);
			sleep(decision.delayMs);
			if (decision.blocked) {
				AttackLog.getInstance().recordEvent(new AttackLog.SecurityEvent(
					System.currentTimeMillis(), req.getRemoteAddress(), req.getMethod(), req.getPath(), req.getHost(),
					"throttle event", "warn", "login throttled after failure", username, req.getHeader("User-Agent", "")));
				res.setResponseCode(429);
				res.send();
				return;
			}
			AttackLog.getInstance().recordEvent(new AttackLog.SecurityEvent(
				System.currentTimeMillis(), req.getRemoteAddress(), req.getMethod(), req.getPath(), req.getHost(),
				"auth failure", "info", "login failed", username, req.getHeader("User-Agent", "")));
		}
		else {
			resetThrottle(req, username);
		}
		redirect(req, res);
	}

	//Attempt a login and return true if it succeeded.
	private boolean login(
						HttpRequest req, HttpResponse res,
						String username, String password) {

		boolean passed = false;
		Authenticator authenticator = Authenticator.getInstance();
		if ((username != null) && (password != null)) {
			User user = Users.getInstance().authenticate(username, password, req);
			if (user != null) {
				passed = authenticator.createSession(user, req, res);
				logger.debug("Response headers:\n"+res.listHeaders("  "));
			}
		}
		if (!passed) authenticator.closeSession(req, res);
		logger.debug("login passed = "+passed);
		return passed;
	}

	//Redirect to a specified URL or to a URL related to the path
	//by which the servlet was accessed. If the url query param
	//is supplied, redirect to it. Otherwise, if the path ends at
	//the context, go to the parent of the last path element.
	//If the path does not end at the context, go to the full path.
	private void redirect(HttpRequest req, HttpResponse res) {
		String url = req.getParameter("url");
		if (url == null) {
			url = req.getPath();
			if (url.endsWith("/"+context)) {
				url = url.substring(0, url.length() - context.length());
			}
		}
		logger.debug("Redirect URL before test: \""+url+"\"");
		if (url.equals("") || isAttack(req, url) || !isAllowedRedirectTarget(url)) url = "/";
		logger.debug("Redirect URL after test: \""+url+"\"");
		res.redirect(url);
	}

	//Allow only root-relative redirects. Reject absolute/scheme-relative paths.
	private boolean isAllowedRedirectTarget(String urlString) {
		if (urlString == null) return false;
		if (!urlString.startsWith("/")) return false;
		if (urlString.startsWith("//")) return false;
		if (urlString.contains("\\")) return false;
		return true;
	}

	//Check a path for characters that indicate a cross-site scripting attack
	private boolean isAttack(HttpRequest req, String path) {
		boolean attack =  path.contains("\n")
							|| path.contains("\r")
							|| path.contains("<")
							|| path.contains(">")
							|| path.contains("%")
							|| path.contains("javascript");
		if (attack) {
			AttackLog.getInstance().recordEvent(new AttackLog.SecurityEvent(
				System.currentTimeMillis(),
				req.getRemoteAddress(),
				req.getMethod(),
				req.getPath(),
				req.getHost(),
				"suspicious redirect",
				"warn",
				"login redirect attack pattern",
				"",
				req.getHeader("User-Agent", "")));
			logger.warn("Attack detected from "+req.getRemoteAddress());
		}
		return attack;
	}

	private ThrottleDecision evaluateThrottle(HttpRequest req, String username) {
		String key = getThrottleKey(req, username);
		ThrottleState state = throttleStates.get(key);
		long now = System.currentTimeMillis();
		if (state == null) return new ThrottleDecision(false, 0);
		synchronized (state) {
			if ((now - state.lastFailureMs) > RESET_INACTIVITY_MS) {
				throttleStates.remove(key);
				return new ThrottleDecision(false, 0);
			}
			if ((now - state.windowStartMs) > FAILURE_WINDOW_MS) {
				state.windowStartMs = now;
				state.failures = 0;
			}
			if (state.failures >= MAX_FAILURES) {
				long delay = computeDelay(state.failures - MAX_FAILURES + 1);
				return new ThrottleDecision(true, delay);
			}
			return new ThrottleDecision(false, 0);
		}
	}

	private ThrottleDecision registerFailure(HttpRequest req, String username) {
		pruneThrottleStates();
		String key = getThrottleKey(req, username);
		long now = System.currentTimeMillis();
		ThrottleState state = throttleStates.computeIfAbsent(key, k -> new ThrottleState(now));
		synchronized (state) {
			if ((now - state.windowStartMs) > FAILURE_WINDOW_MS) {
				state.windowStartMs = now;
				state.failures = 0;
			}
			state.failures++;
			state.lastFailureMs = now;
			if (state.failures >= MAX_FAILURES) {
				long delay = computeDelay(state.failures - MAX_FAILURES + 1);
				return new ThrottleDecision(true, delay);
			}
			return new ThrottleDecision(false, computeDelay(0));
		}
	}

	private void resetThrottle(HttpRequest req, String username) {
		throttleStates.remove(getThrottleKey(req, username));
	}

	private void pruneThrottleStates() {
		long now = System.currentTimeMillis();
		for (String key : throttleStates.keySet()) {
			ThrottleState state = throttleStates.get(key);
			if ((state != null) && ((now - state.lastFailureMs) > RESET_INACTIVITY_MS)) throttleStates.remove(key);
		}
		if (throttleStates.size() < MAX_THROTTLE_STATES) return;
		int removeCount = throttleStates.size() - MAX_THROTTLE_STATES + 1;
		for (String key : throttleStates.keySet()) {
			throttleStates.remove(key);
			if (--removeCount <= 0) break;
		}
	}

	private String getThrottleKey(HttpRequest req, String username) {
		String ip = req.getRemoteAddress();
		if (ip == null) ip = "unknown";
		String user = (username == null) ? "" : username.trim().toLowerCase();
		return ip + "|" + user;
	}

	private long computeDelay(int exponent) {
		int exp = Math.max(0, exponent);
		long delay = 250L * (1L << Math.min(3, exp));
		return Math.min(MAX_DELAY_MS, delay);
	}

	private void sleep(long ms) {
		if (ms <= 0) return;
		try { Thread.sleep(ms); }
		catch (Exception ignore) { }
	}

	static class ThrottleState {
		long windowStartMs;
		long lastFailureMs;
		int failures;
		ThrottleState(long now) {
			this.windowStartMs = now;
			this.lastFailureMs = now;
			this.failures = 0;
		}
	}

	static class ThrottleDecision {
		final boolean blocked;
		final long delayMs;
		ThrottleDecision(boolean blocked, long delayMs) {
			this.blocked = blocked;
			this.delayMs = delayMs;
		}
	}
}
