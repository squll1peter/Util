/*---------------------------------------------------------------
*  Copyright 2015 by the Radiological Society of North America
*
*  This source software is released under the terms of the
*  RSNA Public License (http://mirc.rsna.org/rsnapubliclicense.pdf)
*----------------------------------------------------------------*/

package org.rsna.servlets;

import java.io.File;
import java.io.InputStream;
import java.util.Hashtable;
import org.rsna.server.HttpRequest;
import org.rsna.server.HttpResponse;

import org.apache.log4j.Logger;
import org.rsna.util.Attack;
import org.rsna.util.AttackLog;
import org.rsna.util.AttackLog.SecurityEvent;
import org.rsna.util.FileUtil;
import org.rsna.util.StringUtil;
import org.rsna.util.XmlUtil;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * The Attack Log Servlet.
 * This servlet provides a viefw of the AttackLog.
 */
public class AttackLogServlet extends Servlet {

	static final Logger logger = Logger.getLogger(AttackLogServlet.class);
	String home = "/";


	/**
	 * Construct an AttackLogServlet.
	 * @param root the root directory of the server.
	 * @param context the path identifying the servlet.
	 */
	public AttackLogServlet(File root, String context) {
		super(root, context);
	}

	/**
	 * The servlet method that responds to an HTTP GET.
	 * @param req the request object.
	 * @param res the response object.
	 */
	public void doGet(HttpRequest req, HttpResponse res) throws Exception {
		res.setContentEncoding(req);

		//Require that the user have the admin role
		if (!req.userHasRole("admin")) {
			res.setResponseCode(res.notfound);
			res.send();
			return;
		}

		if (req.hasParameter("suppress")) home = "";

		//Make the page and return it.
		Document xml = XmlUtil.getDocument();
		Element root = xml.createElement("Attackers");
		xml.appendChild(root);

		//Put in the attackers
		Attack[] attacks = AttackLog.getInstance().getAttacks();
		for (Attack attack : attacks) {
			String ip = attack.getIP();
			String city = attack.getCity();
			String region = attack.getRegion();
			String country = attack.getCountry();
			int count = attack.getCount();
			String last = StringUtil.getDateTime(attack.getLast(), " ");
			Element e = xml.createElement("Attacker");
			e.setAttribute("ip", ip);
			e.setAttribute("city", city);
			e.setAttribute("region", region);
			e.setAttribute("country", country);
			e.setAttribute("count", Integer.toString(count));
			e.setAttribute("last", last);
			root.appendChild(e);
		}

		//Add aggregate category counts
		Element categories = xml.createElement("Categories");
		root.appendChild(categories);
		Hashtable<String,Integer> categoryCounts = AttackLog.getInstance().getCategoryCounts();
		for (String category : categoryCounts.keySet()) {
			Element e = xml.createElement("Category");
			e.setAttribute("name", category);
			e.setAttribute("count", Integer.toString(categoryCounts.get(category)));
			categories.appendChild(e);
		}

		//Add recent events
		Element events = xml.createElement("RecentEvents");
		root.appendChild(events);
		for (SecurityEvent event : AttackLog.getInstance().getRecentEvents()) {
			Element e = xml.createElement("Event");
			e.setAttribute("timestamp", StringUtil.getDateTime(event.timestamp, " "));
			e.setAttribute("ip", event.remoteIP);
			e.setAttribute("method", event.method);
			e.setAttribute("path", event.path);
			e.setAttribute("host", event.host);
			e.setAttribute("category", event.category);
			e.setAttribute("severity", event.severity);
			e.setAttribute("detail", event.detail);
			events.appendChild(e);
		}

		Document xsl = XmlUtil.getDocument(FileUtil.getStream("/AttackLogServlet.xsl"));
		String[] params = new String[] { "home", home };
		res.write( XmlUtil.getTransformedText( xml, xsl, params ) );
		res.setContentType("html");
		res.disableCaching();
		res.send();
	}
}
