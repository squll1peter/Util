/*---------------------------------------------------------------
*  Copyright 2015 by the Radiological Society of North America
*
*  This source software is released under the terms of the
*  RSNA Public License (http://mirc.rsna.org/rsnapubliclicense.pdf)
*----------------------------------------------------------------*/

package org.rsna.util;

import java.net.HttpURLConnection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.log4j.Logger;
import org.rsna.util.FileUtil;
import org.rsna.util.HttpUtil;
import org.rsna.util.XmlUtil;

/**
 * A singleton log of server attacks.
 */
public class AttackLog {

	static final Logger logger = Logger.getLogger(AttackLog.class);
	static AttackLog attackLog = null;
	private static final int MAX_RECENT_EVENTS = 1000;
	private Hashtable<String,Attack> attackTable;
	private LinkedList<SecurityEvent> recentEvents;
	private Hashtable<String,Integer> categoryCounts;
	final int readTimeout = 60000;

	/**
	 * The protected constructor to prevent instantiation of
	 * the class except through the getInstance() method.
	 */
	protected AttackLog() {
		this.attackTable = new Hashtable<String,Attack>();
		this.recentEvents = new LinkedList<SecurityEvent>();
		this.categoryCounts = new Hashtable<String,Integer>();
	}

	/**
	 * Get the AttackLog instance, creating it if it does not exist.
	 * @return the AttackLog instance.
	 */
	public synchronized static AttackLog getInstance() {
		if (attackLog == null) attackLog = new AttackLog();
		return attackLog;
	}

	/**
	 * Add an attack to the AttackLog.
	 * @param ip the IP address of the attacker.
	 */
    public synchronized void addAttack(String ip) {
		recordEvent(new SecurityEvent(
			System.currentTimeMillis(),
			ip,
			"",
			"",
			"",
			"malformed request",
			"warn",
			"request parse failure",
			"",
			""));
	}

	/**
	 * Record a structured security event.
	 * @param event the event to add.
	 */
	public synchronized void recordEvent(SecurityEvent event) {
		if (event == null) return;
		String ip = sanitize(event.remoteIP);
		Attack attack = attackTable.get(ip);
		if (attack == null) attack = new Attack(ip);
		attack.increment();
		attack.setLast(event.timestamp);
		attackTable.put(ip, attack);

		String category = sanitize(event.category);
		Integer count = categoryCounts.get(category);
		categoryCounts.put(category, (count == null) ? 1 : count + 1);

		recentEvents.add(new SecurityEvent(event));
		while (recentEvents.size() > MAX_RECENT_EVENTS) recentEvents.removeFirst();
		logger.info("Security event logged ["+category+"] from "+ip);
	}

	/**
	 * Get the array of attacks, sorted in reverse chronological order by last attack.
	 * @return the sorted array of attacks; where the array is populated with new
	 * instances, protecting the ones in the AttackLog.
	 */
	public synchronized Attack[] getAttacks() {
		Attack[] attacks = new Attack[attackTable.size()];
		attacks = attackTable.values().toArray(attacks);
		Attack[] atks = new Attack[attacks.length];
		for (int i=0; i<atks.length; i++) {
			atks[i] = new Attack(attacks[i]);
		}
		Arrays.sort(atks);
		return atks;
	}

	/**
	 * Get a defensive snapshot of recent events, newest-first.
	 * @return list of security events.
	 */
	public synchronized List<SecurityEvent> getRecentEvents() {
		ArrayList<SecurityEvent> events = new ArrayList<SecurityEvent>();
		for (SecurityEvent e : recentEvents) events.add(new SecurityEvent(e));
		Collections.reverse(events);
		return events;
	}

	/**
	 * Get aggregate event counts by category.
	 * @return snapshot map of counts.
	 */
	public synchronized Hashtable<String,Integer> getCategoryCounts() {
		Hashtable<String,Integer> copy = new Hashtable<String,Integer>();
		for (String key : categoryCounts.keySet()) {
			copy.put(key, categoryCounts.get(key));
		}
		return copy;
	}

	private String sanitize(String s) {
		return (s == null) ? "" : s;
	}

	private void getInfo(Attack attack) {
		if ((attack != null) && attack.getCountry().equals("")) {
			String ip = attack.getIP();
			String url = "https://secure.geobytes.com/GetCityDetails?key=7c756203dbb38590a66e01a5a3e1ad96&fqcn="+ip;
			try {
				HttpURLConnection conn = HttpUtil.getConnection(url);
				conn.setReadTimeout(readTimeout);
				conn.setRequestMethod("GET");
				conn.connect();
				if (conn.getResponseCode() == HttpURLConnection.HTTP_OK) {
					String result = FileUtil.getText( conn.getInputStream(), FileUtil.latin1 );
					JSONTable table = new JSONTable(result);
					attack.setCity(table.get("geobytescity"));
					attack.setRegion(table.get("geobytesregion"));
					attack.setCountry(table.get("geobytescountry"));
				}
			}
			catch (Exception skip) { }
		}
	}
	
/* Example result from geobytes (with newlines added for readability):

{"geobytesinternet":"AU","geobytescountry":"Australia","geobytesregionlocationcode":"AUSA",
"geobytesregion":"South Australia","geobytescode":"SA","geobyteslocationcode":"AUSAADEL",
"geobytescity":"Adelaide","geobytescityid":"1312","geobytesfqcn":"Adelaide, SA, Australia",
"geobyteslatitude":"-34.932999","geobyteslongitude":"138.600006","geobytescapital":"Canberra ",
"geobytestimezone":"138.6","geobytesnationalitysingular":"Australian","geobytespopulation":"19357594",
"geobytesnationalityplural":"Australians","geobytesmapreference":"Oceania ",
"geobytescurrency":"Australian dollar ","geobytescurrencycode":"AUD","geobytestitle":"Australia"}

*/
	class JSONTable extends Hashtable<String,String> {
		public JSONTable(String text) throws Exception {
			super();
			Pattern pattern = Pattern.compile("\"([^\"]*)\":\"([^\"]*)\"");
			Matcher matcher = pattern.matcher(text);
			while (matcher.find()) {
				String key = matcher.group(1);
				String value = matcher.group(2);
				put(key, value);
			}
		}
	}

	/**
	 * Structured security-event record for in-memory attack telemetry.
	 */
	public static class SecurityEvent {
		public final long timestamp;
		public final String remoteIP;
		public final String method;
		public final String path;
		public final String host;
		public final String category;
		public final String severity;
		public final String detail;
		public final String username;
		public final String userAgent;

		public SecurityEvent(
				long timestamp,
				String remoteIP,
				String method,
				String path,
				String host,
				String category,
				String severity,
				String detail,
				String username,
				String userAgent) {
			this.timestamp = timestamp;
			this.remoteIP = remoteIP;
			this.method = method;
			this.path = path;
			this.host = host;
			this.category = category;
			this.severity = severity;
			this.detail = detail;
			this.username = username;
			this.userAgent = userAgent;
		}

		public SecurityEvent(SecurityEvent event) {
			this.timestamp = event.timestamp;
			this.remoteIP = event.remoteIP;
			this.method = event.method;
			this.path = event.path;
			this.host = event.host;
			this.category = event.category;
			this.severity = event.severity;
			this.detail = event.detail;
			this.username = event.username;
			this.userAgent = event.userAgent;
		}
	}
}
