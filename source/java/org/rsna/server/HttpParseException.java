/*---------------------------------------------------------------
*  Copyright 2026 by the Radiological Society of North America
*
*  This source software is released under the terms of the
*  RSNA Public License (http://mirc.rsna.org/rsnapubliclicense.pdf)
*----------------------------------------------------------------*/

package org.rsna.server;

/**
 * Exception describing an HTTP parse failure with response status.
 */
public class HttpParseException extends Exception {

	private final int statusCode;
	private final String category;

	public HttpParseException(int statusCode, String category, String message) {
		super(message);
		this.statusCode = statusCode;
		this.category = category;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public String getCategory() {
		return category;
	}
}
