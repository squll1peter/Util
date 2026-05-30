/*---------------------------------------------------------------
*  Copyright 2015 by the Radiological Society of North America
*
*  This source software is released under the terms of the
*  RSNA Public License (http://mirc.rsna.org/rsnapubliclicense.pdf)
*----------------------------------------------------------------*/

package org.rsna.server;

import java.io.File;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Iterator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.apache.log4j.Logger;
import org.rsna.util.DigestUtil;
import org.rsna.util.FileUtil;
import org.rsna.util.XmlUtil;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NamedNodeMap;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

/**
 * A class to extend the org.rsna.server.Users abstract class
 * for managing the users.xml file. This file is located in the root
 * of the application.
 */
public class UsersXmlFileImpl extends Users {

	static final Logger logger = Logger.getLogger(UsersXmlFileImpl.class);

	static String usersFileName = "users.xml";
	static final String PBKDF2_PREFIX = "pbkdf2$";
	static final int PBKDF2_ITERATIONS = 100000;
	static final int PBKDF2_SALT_BYTES = 16;
	static final int PBKDF2_KEY_BITS = 256;
	File usersFile = null;
	Hashtable<String,User> users = null;
	HashSet<String> roles = null;
	boolean bootstrapLocalOnly = false;
	final SecureRandom secureRandom = new SecureRandom();

	/**
	 * Constructor.
	 * @param element ignored in this implementation of the Users class.
	 */
	public UsersXmlFileImpl(Element element) {
		//Load the roles table.
		roles = new HashSet<String>();

		//Load the users table from the XML file, creating
		//an empty XML file if it does not exist.
		usersFile = new File(usersFileName);
		if (!usersFile.exists()) {
			bootstrapLocalOnly = true;
			FileUtil.setText(usersFile, getEmptyUsersText());
		}
		users = getUsers();
	}

	//Get all the User objects in a Hashtable indexed by username.
	//This method converts the file to digest mode if it is not
	private synchronized Hashtable<String,User> getUsers() {
		Hashtable<String,User> hashtable = new Hashtable<String,User>();

		Document usersXML;
		try { usersXML = XmlUtil.getDocument(usersFile); }
		catch (Exception ex) {
			logger.warn("Unable to parse the users file: "+usersFile);
			return hashtable;
		}

		Element root = usersXML.getDocumentElement();
		bootstrapLocalOnly = root.getAttribute("bootstrapLocalOnly").equals("true");
		boolean isHashed = root.getAttribute("mode").equals("digest");
		Node userChild = root.getFirstChild();
		while (userChild != null) {
			if ((userChild instanceof Element) && userChild.getNodeName().equals("user")) {
				Element userElement = (Element)userChild;
				String username = userElement.getAttribute("username");
				String password = userElement.getAttribute("password");
				if (!isHashed) password = convertPassword(password);
				User user = new User(username, password);
				Node roleChild = userElement.getFirstChild();
				while (roleChild != null) {
					if ((roleChild instanceof Element) && roleChild.getNodeName().equals("role")) {
						user.addRole(roleChild.getTextContent());
					}
					roleChild = roleChild.getNextSibling();
				}
				hashtable.put(username,user);
			}
			userChild = userChild.getNextSibling();
		}
		if (!isHashed) resetUsers(hashtable);
		return hashtable;
	}

	/**
	 * Get all the usernames in an alphabetized array.
	 * @return the array of usernames or a zero-length array if unable.
	 */
	public synchronized int getNumberOfUsers() {
		return users.size();
	}

	/**
	 * Get all the usernames in an alphabetized array.
	 * @return the array of usernames or a zero-length array if unable.
	 */
	public synchronized String[] getUsernames() {
		if (users == null) return new String[0];
		String[] usernames = new String[users.size()];
		usernames = users.keySet().toArray(usernames);
		Arrays.sort(usernames);
		return usernames;
	}

	/**
	 * Convert a plaintext password to the form used by this users implementation.
	 * @param password the password in plaintext
	 * @return the converted password.
	 */
	public String convertPassword(String password) {
		return createPBKDF2Hash(password);
	}

	/**
	 * Add a role name.
	 * @param role the role name.
	 */
	public synchronized void addRole(String role) {
		roles.add(role);
	}

	/**
	 * Remove a role name.
	 * @param role the role name.
	 */
	public synchronized void removeRole(String role) {
		roles.remove(role);
	}

	/**
	 * Get all the role names in a HashSet.
	 * @return the HashSet of role names or null if unable.
	 */
	public synchronized HashSet<String> getRoles() {
		if (users == null) return null;
		//Put in all the roles from the table,
		//just in case somebody has created new roles.
		for (User user : users.values()) {
			roles.addAll(user.getRoles());
		}
		return roles;
	}

	/**
	 * Get all the role names in an alphabetized array.
	 * @return the array of role names or a zero-length array if unable.
	 */
	public synchronized String[] getRoleNames() {
		HashSet<String> hashset = getRoles();
		if (hashset == null) return new String[0];
		String[] names = new String[hashset.size()];
		names = hashset.toArray(names);
		Arrays.sort(names);
		return names;
	}

	/**
	 * Reset the database of users.
	 * @param users the table of users to put in the database.
	 */
	public synchronized void resetUsers(Hashtable<String,User> users) {
		this.users = users;
		FileUtil.setText(usersFile, getUsersText());
	}

	/**
	 * Get a specific user.
	 * @param username the username
	 * @return the user or null if unable.
	 */
	public synchronized User getUser(String username) {
		return users.get(username);
	}

	/**
	 * Create a user, converting the password. This method does
	 * not add the user to the database. Call addUser if you
	 * want to do that.
	 * @param username the username in plaintext.
	 * @param password the password in plaintext.
	 * @return the user.
	 */
	public User createUser(String username, String password) {
		return new User(username, convertPassword(password));
	}

	/**
	 * Check whether a set of credentials match a user in the system.
	 * @param username the username in plaintext.
	 * @param password the password in plaintext.
	 * @return true if the credentials match a user; false otherwise.
	 */
	public User authenticate(String username, String password) {
		return authenticate(username, password, null);
	}

	public User authenticate(String username, String password, HttpRequest req) {
		if (bootstrapLocalOnly && ((req == null) || !req.isFromLocalHost())) return null;
		User user = getUser(username);
		if (user != null) {
			String stored = user.getPassword();
			if (isPBKDF2(stored)) {
				if (verifyPBKDF2(password, stored)) return user;
			}
			else {
				String pw = DigestUtil.hash(password);
				if (constantTimeEquals(stored, pw)) {
					user.setPassword(createPBKDF2Hash(password));
					addUser(user); //migrate legacy MD5 to PBKDF2
					return user;
				}
			}
		}
		return null;
	}

	/**
	 * Add a user to the database or update the user if it exists.
	 * This method always updates the users.xml file.
	 * @param user the user to add or update.
	 */
	public synchronized void addUser(User user) {
		if ((user != null) && (users != null)) {
			if (!isPBKDF2(user.getPassword())) user.setPassword(createPBKDF2Hash(user.getPassword()));
			bootstrapLocalOnly = false;
			users.put(user.getUsername(), user);
			FileUtil.setText(usersFile, getUsersText());
		}
	}

	/**
	 * Remove a user from the database and update the users.xml file.
	 * @param username the user to remove.
	 */
	public synchronized void removeUser(String username) {
		if ((username != null) && (users != null)) {
			if (users.remove(username) != null) {
				FileUtil.setText(usersFile, getUsersText());
			}
		}
	}

	/**
	 * Get the users in an XML Document.
	 * @return the XML Document containing all the users
	 */
	public Document getXML() {
		try {
			Document doc = XmlUtil.getDocument();
			Element root = doc.createElement("users");
			root.setAttribute("mode", "digest");
			root.setAttribute("bootstrapLocalOnly", Boolean.toString(bootstrapLocalOnly));
			doc.appendChild(root);
			String[] names = getUsernames();
			for (String name : names) {
				User user = users.get(name);
				Element userElement = doc.createElement("user");
				root.appendChild(userElement);
				userElement.setAttribute("username", user.getUsername());
				userElement.setAttribute("password", user.getPassword());
				for (String role : user.getRoles()) {
					Element roleElement = doc.createElement("role");
					roleElement.setTextContent(role);
					userElement.appendChild(roleElement);
				}
			}
			return doc;
		}
		catch (Exception ex) { return null; }
	}

	private String getUsersText() {
		return XmlUtil.toPrettyString(getXML());
	}

	private String getEmptyUsersText() {
		return
			"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
			"<users bootstrapLocalOnly=\"true\">" +
				"<user username=\"king\" password=\"password\">" +
					"<role>admin</role>" +
					getUserRoles() +
					"<role>shutdown</role>" +
				"</user>" +
				"<user username=\"admin\" password=\"password\">" +
					"<role>admin</role>" +
					getUserRoles() +
				"</user>" +
			"</users>";
	}

	private boolean isPBKDF2(String value) {
		return (value != null) && value.startsWith(PBKDF2_PREFIX);
	}

	private String createPBKDF2Hash(String password) {
		try {
			if (password == null) password = "";
			byte[] salt = new byte[PBKDF2_SALT_BYTES];
			secureRandom.nextBytes(salt);
			byte[] hash = derivePBKDF2(password.toCharArray(), salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BITS);
			return PBKDF2_PREFIX
				+ PBKDF2_ITERATIONS + "$"
				+ Base64.getEncoder().encodeToString(salt) + "$"
				+ Base64.getEncoder().encodeToString(hash);
			}
			catch (Exception ex) {
				throw new IllegalStateException("Unable to create PBKDF2 password hash", ex);
			}
	}

	private boolean verifyPBKDF2(String password, String stored) {
		try {
			String[] parts = stored.split("\\$");
			if (parts.length != 4) return false;
			int iterations = Integer.parseInt(parts[1]);
			byte[] salt = Base64.getDecoder().decode(parts[2]);
			byte[] expected = Base64.getDecoder().decode(parts[3]);
			byte[] actual = derivePBKDF2(password.toCharArray(), salt, iterations, expected.length * 8);
			return MessageDigest.isEqual(expected, actual);
		}
		catch (Exception ex) { return false; }
	}

	private byte[] derivePBKDF2(char[] password, byte[] salt, int iterations, int keyBits) throws Exception {
		PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, keyBits);
		SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
		return skf.generateSecret(spec).getEncoded();
	}

	private boolean constantTimeEquals(String a, String b) {
		if ((a == null) || (b == null)) return false;
		return MessageDigest.isEqual(a.getBytes(), b.getBytes());
	}

	//Get the non-administrative roles
	private String getUserRoles() {
		StringBuffer sb = new StringBuffer();
		String[] roles = getRoleNames();
		for (String role : roles) {
			if (!role.equals("admin") && !role.equals("shutdown")) {
				sb.append("<role>"+role.trim()+"</role>");
			}
		}
		return sb.toString();
	}

}
