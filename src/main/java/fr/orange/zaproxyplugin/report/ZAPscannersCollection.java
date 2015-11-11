/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 ludovicRoucoux
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package  fr.orange.zaproxyplugin.report;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;

/**
 * This class contains all ZAPreport instance of the application. It's a
 * singleton class so the application contains only one instance of the class.
 * 
 * @author ludovic.roucoux
 *
 */
public class ZAPscannersCollection implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1335367990441760922L;

	private static ZAPscannersCollection uniqueInstance = new ZAPscannersCollection();

	/**
	 * Map where key is the report format represented by a String and value is a
	 * ZAPreport object allowing to generate a report with the corresponding
	 * format.
	 */
	private Map<String, String> mapScannersTypes;

	private ZAPscannersCollection() {
		mapScannersTypes = new HashMap<String, String>();

		// Add SCANNERS to the map
		mapScannersTypes.put("ALL SCANNERS", "ALL");
		
		mapScannersTypes.put("Cross Site Scripting (Reflected)", "40012");
		mapScannersTypes.put("Cross Site Scripting (Persistent)", "40014");
		mapScannersTypes.put("Cross Site Scripting (Persistent) - Prime", "40016");
		mapScannersTypes.put("Cross Site Scripting (Persistent) - Spider", "40017");
		mapScannersTypes.put("SQL Injection", "40018");
		
//		mapScannersTypes.put("Anti CSRF tokens scanner", "20012");
//		mapScannersTypes.put("HTTP Parameter Pollution scanner", "20014");
//		mapScannersTypes.put("Session Fixation", "40013");
//		mapScannersTypes.put("LDAP Injection", "40015");
//		mapScannersTypes.put("SQL Injection - MySQL", "40019");
//		mapScannersTypes.put("SQL Injection - Hypersonic SQL", "40020");
//		mapScannersTypes.put("SQL Injection - Oracle", "40021");
//		mapScannersTypes.put("SQL Injection - PostgreSQL", "40022");
//		mapScannersTypes.put("Possible Username Enumeration", "40023");
//		mapScannersTypes.put("XPath Injection Plugin", "90021");
//		mapScannersTypes.put("XML External Entity Attack", "90023");
//		
		
		
		mapScannersTypes.put("Server Side Code Injection", "90019");
		mapScannersTypes.put(" Remote OS Command Injection Plugin", "90020");
		mapScannersTypes.put("Directory browsing", "0");
		mapScannersTypes.put("Path Traversal", "6");
		mapScannersTypes.put("Remote File Inclusion", "7");
		mapScannersTypes.put("Secure page browser cache", "10001");
		mapScannersTypes.put("External redirect", "30000");
		mapScannersTypes.put("CRLF injection", "40003");
		mapScannersTypes.put("Parameter tampering", "40008");
		mapScannersTypes.put("Server side include", "40009");

	}

	public static ZAPscannersCollection getInstance() {
		if (uniqueInstance == null)
			uniqueInstance = new ZAPscannersCollection();

		return uniqueInstance;
	}

	public Map<String, String> getMapScannersTypes() {
		return mapScannersTypes;
	}
}
