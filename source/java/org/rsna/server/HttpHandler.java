/*---------------------------------------------------------------
*  Copyright 2015 by the Radiological Society of North America
*
*  This source software is released under the terms of the
*  RSNA Public License (http://mirc.rsna.org/rsnapubliclicense.pdf)
*----------------------------------------------------------------*/

package org.rsna.server;

import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import org.apache.log4j.Logger;
import org.rsna.servlets.LoginServlet;
import org.rsna.servlets.Servlet;
import org.rsna.util.AttackLog;

/**
 * The thread that handles an individual HTTP connection.
 */
public class HttpHandler extends Thread {

	static final Logger logger = Logger.getLogger(HttpHandler.class);

	Socket socket;
	HttpServer server;
	ServletSelector selector;
	HttpResponse res = null;
	HttpRequest req = null;

	/**
	 * Construct an HttpHandler.
	 * @param socket the socket on which the connection was received.
	 * @param selector the class that decodes request paths into servlet calls
	 * @param server the HttpServer to pass to HttpRequest
	 */
	public HttpHandler(Socket socket, ServletSelector selector, HttpServer server) {
		super("HttpHandler");
		this.socket = socket;
		this.selector = selector;
		this.server = server;
	}

	/**
	 * Handle the connection in a separate Thread, getting the streams,
	 * selecting a Servlet to handle the request, and returning the response.
	 */
	public void run() {

		try {
			//Make a response
			res = new HttpResponse(socket);

			//Get the request
			req = new HttpRequest(socket, server);
			
			//Get the Servlet, applying the global auth gate before dispatch.
			Servlet servlet = selectServlet(req);

			//Call the appropriate method
			if (req.method.equals("GET")) {
				servlet.doGet(req, res);
			}
			else if (req.method.equals("POST")) {
				servlet.doPost(req, res);
			}
			else if (req.method.equals("PUT")) {
				servlet.doPut(req, res);
			}
			else if (req.method.equals("DELETE")) {
				servlet.doDelete(req, res);
			}
			else if (req.method.equals("OPTIONS")) {
				servlet.doOptions(req, res);
			}
			else if (req.method.equals("")) {
				//Do not send a response
			}
			else {
				res.setResponseCode(res.notallowed);
				res.send();
				recordSecurityEvent(req, "unsupported method", "warn", "unsupported HTTP method");
				logger.debug("Unallowed method in request ("+req.method+") received from "+req.getRemoteAddress());
			}
		}
		catch (HttpParseException hpe) {
			try {
				res = new HttpResponse(socket);
				res.setResponseCode(hpe.getStatusCode());
				res.send();
			}
			catch (Exception ignore) { }
			String remoteIP = "unknown";
			try { remoteIP = req.getRemoteAddress(); } catch (Exception ignore) { }
			AttackLog.getInstance().recordEvent(new AttackLog.SecurityEvent(
				System.currentTimeMillis(),
				remoteIP,
				(req != null) ? req.getMethod() : "",
				(req != null) ? req.getPath() : "",
				(req != null) ? req.getHost() : "",
				hpe.getCategory(),
				"warn",
				hpe.getMessage(),
				"",
				(req != null) ? req.getHeader("User-Agent", "") : ""));
			logger.warn("HTTP parse failure ("+hpe.getCategory()+") from " + socket.getRemoteSocketAddress() + ": " + hpe.getMessage());
		}
		catch (Exception ex) {
			if (req != null) {
				logger.error("Internal server error ("+req.toSafeString()+")",ex);
				recordSecurityEvent(req, "internal error", "error", "servlet processing failed");
				try {
					res = new HttpResponse(socket);
					res.setResponseCode(res.servererror);
					res.write("<html>");
					res.write("<head><title>ERROR</title></head>");
					res.write("<body><h1>Internal Server Error (HTTP 500)</h1></body>");
					res.write("</html>");
					res.send();
				}
				catch (Exception ignore) { /*Don't log this; the real problem has been logged above.*/ }
			}
			else { logger.error("Internal server error (req==null)",ex); }
		}
		//Close everything.
		if (req != null) req.close();
		if (res != null) res.close();
		try { socket.close(); }
		catch (Exception ex) { logger.info("Unable to close the socket."); }
	}

	private Servlet selectServlet(HttpRequest req) {
		Path path = req.getParsedPath();
		String pathElement = path.element(0);
		if (selector.getRequireAuthentication() && (req.getUser() == null)
				&& !isPublicPath(pathElement)
				&& !isLocalShutdownRequest(req, path, pathElement)) {
			return new LoginServlet(selector.getRoot(), "");
		}
		return selector.getServlet(req);
	}

	private boolean isPublicPath(String pathElement) {
		return pathElement.equals("login")
				|| pathElement.equals("login.html")
				|| pathElement.equals("BaseStyles.css")
				|| pathElement.equals("ping");
	}

	private boolean isLocalShutdownRequest(HttpRequest req, Path path, String pathElement) {
		return (req.getHeader("servicemanager") != null)
				&& (path.length() == 1)
				&& pathElement.equals("shutdown")
				&& req.isFromLocalHost();
	}

	private void recordSecurityEvent(HttpRequest req, String category, String severity, String detail) {
		AttackLog.getInstance().recordEvent(new AttackLog.SecurityEvent(
			System.currentTimeMillis(),
			req.getRemoteAddress(),
			req.getMethod(),
			req.getPath(),
			req.getHost(),
			category,
			severity,
			detail,
			"",
			req.getHeader("User-Agent", "")));
	}
}
