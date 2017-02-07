
/*
 * The MIT License (MIT)
 *
 * Copyright (c) 2015 Abdellah AZOUGARH
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

package fr.hackthem.zapkins.api;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseFactory;
import org.zaproxy.clientapi.core.ClientApiException;

import hudson.FilePath;
import hudson.model.BuildListener;
import hudson.util.FormValidation;
import fr.hackthem.zapkins.utilities.HttpUtilities;
import fr.hackthem.zapkins.utilities.ProxyAuthenticator;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;

public class CustomZapClientApi implements Serializable {

	private static final long serialVersionUID = 3961600153488729709L;
	private static final int MILLISECONDS_IN_SECOND = 1000;

	private final String zapProxyKey;
	public final CustomZapApi api;
	private final boolean debug;

	private BuildListener listener;
	private String PROTOCOL;

	/*******************************************
	 * Constructeurs de classe
	 *****************************************************/

	public CustomZapClientApi(String ZAP_ADDRESS, int zapProxyPort, String ZAP_API_KEY, BuildListener listener,
			boolean debug) {
		super();

		this.zapProxyKey = ZAP_API_KEY;
		this.listener = listener;
		this.debug = debug;

		this.api = new CustomZapApi(ZAP_ADDRESS, "" + zapProxyPort + "", listener, debug);
	}

	public CustomZapClientApi(String PROTOCOL, String ZAP_ADDRESS, int zapProxyPort, String ZAP_API_KEY,
			BuildListener listener, boolean debug) {
		super();
		this.PROTOCOL = PROTOCOL;
		this.zapProxyKey = ZAP_API_KEY;
		this.listener = listener;
		this.debug = debug;

		this.api = new CustomZapApi(PROTOCOL, ZAP_ADDRESS, "" + zapProxyPort + "", listener, debug);
	}

	public CustomZapClientApi(String zapProxyHost, int zapProxyPort, String zapProxyKey, boolean debug) {

		super();

		this.zapProxyKey = zapProxyKey;
		this.debug = debug;
		this.api = new CustomZapApi(zapProxyHost, "" + zapProxyPort + "", debug);
	}

	/***************************************************************************************************************************/

	public static ApiResponse sendRequest(String protocol, String zapProxyHost, int zapProxyPort, String format,
			String component, String type, String method, Map<String, String> params, Proxy proxy, int timeoutInSec)
					throws IOException, ParserConfigurationException, SAXException, ClientApiException {
		URL url;

		StringBuilder sb = new StringBuilder();
		sb.append(protocol + "://" + zapProxyHost + ":" + zapProxyPort + "/");
		sb.append(format);
		sb.append('/');
		sb.append(component);
		sb.append('/');
		sb.append(type);
		sb.append('/');
		sb.append(method);
		sb.append('/');
		if (params != null) {
			sb.append('?');
			for (Map.Entry<String, String> p : params.entrySet()) {
				sb.append(CustomZapApi.encodeQueryParam(p.getKey()));
				sb.append('=');
				if (p.getValue() != null) {
					sb.append(CustomZapApi.encodeQueryParam(p.getValue()));
				}
				sb.append('&');
			}
		}
		url = new URL(sb.toString());
		HttpURLConnection uc;
		if (proxy != null) {
			uc = (HttpURLConnection) url.openConnection(proxy);
		}

		else {
			uc = (HttpURLConnection) url.openConnection();
		}
		uc.setConnectTimeout(getMilliseconds(timeoutInSec));
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();

		DocumentBuilder db = dbf.newDocumentBuilder();

		Document doc = db.parse(uc.getInputStream());
		return ApiResponseFactory.getResponse(doc.getFirstChild());
	}

	public static FormValidation testZAPConnection(String protocol, String zapProxyHost, int zapProxyPort,
			String zapProxyKey, Proxy proxy, int timeoutInSec) {

		int responseCode = 0;
		try {

			URL url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);

			HttpURLConnection conn;

			if (proxy == null) {
				conn = (HttpURLConnection) url.openConnection();
			} else {

				conn = (HttpURLConnection) url.openConnection(proxy);
			}

			/*
			 * *************************************************************
			 * *******************************
			 */

			conn.setRequestMethod("GET");
			conn.setConnectTimeout(HttpUtilities.getMilliseconds(timeoutInSec));
			System.out.println(String.format("Fetching %s ...", url));

			responseCode = conn.getResponseCode();

			if (responseCode == 200) {

				// faire des nouveaux tests pour valider la clé api
				Map<String, String> map = null;
				map = new HashMap<String, String>();

				if (zapProxyKey != null) {
					map.put("apikey", zapProxyKey);
				}

				ApiResponseElement response;
				// si la clé n'est pas correcte, une exception est lancée

				try {
					response = (ApiResponseElement) sendRequest(protocol, zapProxyHost, zapProxyPort, "xml", "pscan",
							"action", "enableAllScanners", map, proxy, timeoutInSec);
				} catch (IOException e) {
					return FormValidation.error("Invalid or missing API key");
				}

				// si la clé est correcte on affiche la version de ZAP
				// installée
				response = (ApiResponseElement) sendRequest(protocol, zapProxyHost, zapProxyPort, "xml", "core", "view",
						"version", null, proxy, timeoutInSec);

				return FormValidation.okWithMarkup("<br><b><FONT COLOR=\"green\">Success : 200\nSite is up" + "<br>"
						+ "ZAP Proxy(" + response.getName() + ")=" + response.getValue() + "</FONT></b></br>");

			} else {
				System.out.println(String.format("<br>Site is up, but returns non-ok status = %d", responseCode));
				return FormValidation.warning("Site is up, but returns non-ok status = " + responseCode);
			}

		} catch (MalformedURLException e) {

			e.printStackTrace();
			return FormValidation.error(e.getMessage() + "\nHTTP Response code=" + responseCode);
		} catch (IOException e) {

			e.printStackTrace();
			return FormValidation.error(e.getMessage());
		} catch (ParserConfigurationException e) {

			e.printStackTrace();
			return FormValidation.error(e.getMessage() + "\nHTTP Response code=" + responseCode);
		} catch (SAXException e) {

			e.printStackTrace();
			return FormValidation.error(e.getMessage() + "\nHTTP Response code=" + responseCode);
		} catch (ClientApiException e) {

			e.printStackTrace();
			return FormValidation.error(e.getMessage() + "\nHTTP Response code=" + responseCode);
		}

		finally {

			/*
			 * ======================================================= | Stop
			 * ZAP | =======================================================
			 */

			Map<String, String> map = null;
			map = new HashMap<String, String>();
			map.put("apikey", zapProxyKey);
			try {

				sendRequest(protocol, zapProxyHost, zapProxyPort, "xml", "core", "action", "shutdown", map, proxy,
						timeoutInSec);

			} catch (IOException | ParserConfigurationException | SAXException | ClientApiException e) {

				e.printStackTrace();
				return FormValidation.error(e.getMessage());
			}

		}
	}

	public static FormValidation loadAuthenticationScriptsList(String defaultProtocol, String zapProxyDefaultHost,
			int zapProxyPort, String zapProxyDefaultApiKey, Proxy proxy, int zapProxyDefaultTimeoutInSec,
			String ROOT_PATH, String AUTHENTICATION_SCRIPTS_PATH, String AUTHENTICATION_SCRIPTS_LIST_FILE,
			FilePath workspace) {

		/*
		 * ======================================================= | ZAP FILE
		 * PATH SEPARATOR |
		 * =======================================================
		 */

		String FILE_SEPARATOR = "";
		try {

			ApiResponseElement set = (ApiResponseElement) sendRequest(defaultProtocol, zapProxyDefaultHost,
					zapProxyPort, "xml", "core", "view", "homeDirectory", null, proxy, zapProxyDefaultTimeoutInSec);
			String zapHomeDirectory = set.getValue();

			if (zapHomeDirectory.startsWith("/")) {
				FILE_SEPARATOR = "/";
			} else {
				FILE_SEPARATOR = "\\";
			}

			/* ======================================================= */

			StringBuilder sb1 = new StringBuilder();

			ApiResponseList configParamsList = null;
			configParamsList = (ApiResponseList) sendRequest(defaultProtocol, zapProxyDefaultHost, zapProxyPort, "xml",
					"script", "view", "listScripts", null, proxy, zapProxyDefaultTimeoutInSec);

			for (ApiResponse r : configParamsList.getItems()) {
				ApiResponseSet set1 = (ApiResponseSet) r;
				sb1.append(set1.getAttribute("name") + "\n");

			}

			String scripstList = sb1.toString();

			// probleme avec getFILE_SEPARATOR(), avant le build cette
			// fonction doit retourner une valeur
			String filePth = ROOT_PATH + FILE_SEPARATOR + AUTHENTICATION_SCRIPTS_PATH + FILE_SEPARATOR
					+ AUTHENTICATION_SCRIPTS_LIST_FILE;
			if (workspace != null) {
				File scriptsListFile = new File(workspace.getRemote(), filePth);
				FileUtils.writeByteArrayToFile(scriptsListFile, scripstList.getBytes());
			} else {
				// remplir la liste des scripts
				return FormValidation.okWithMarkup("<br><b><FONT COLOR=\"green\">Success : The scripts list is loaded."
						+ "<br>Scripts :<br>" + scripstList + "</FONT></b></br>");
			}

			return FormValidation.okWithMarkup("<br><b><FONT COLOR=\"green\">Success : The scripts list is loaded."
					+ "<br>Please reload the page in order to access to the scripts list</FONT></b></br>");

		} catch (MalformedURLException e1) {

			e1.printStackTrace();
			return FormValidation.error(e1.getMessage());
		}

		catch (ClientApiException e) {

			e.printStackTrace();
			return FormValidation.error(e.getMessage());
		}

		catch (IOException e) {
			e.printStackTrace();
			return FormValidation.error(e.getMessage());

		}

		catch (ParserConfigurationException e) {

			e.printStackTrace();
			return FormValidation.error(e.getMessage());
		} catch (SAXException e) {

			e.printStackTrace();
			return FormValidation.error(e.getMessage());
		}

		finally {

			/*
			 * ======================================================= | Stop
			 * ZAP | =======================================================
			 */

			Map<String, String> map = null;
			map = new HashMap<String, String>();
			map.put("apikey", zapProxyDefaultApiKey);
			try {
				ApiResponseElement set = (ApiResponseElement) CustomZapClientApi.sendRequest(defaultProtocol,
						zapProxyDefaultHost, zapProxyPort, "xml", "core", "action", "shutdown", map, proxy,
						zapProxyDefaultTimeoutInSec);
			} catch (IOException | ParserConfigurationException | SAXException | ClientApiException e) {

				e.printStackTrace();
			}

		}

	}

	/**
	 * Converts seconds in milliseconds.
	 * 
	 * @param seconds
	 *            the time in second to convert
	 * @return the time in milliseconds
	 */
	private static int getMilliseconds(int seconds) {
		return seconds * MILLISECONDS_IN_SECOND;
	}

	/*****************************
	 * USER CONFIG
	 *************************************************************/

	public void listUserConfigInformation(String contextId, BuildListener listener) {

		if (debug) {

			ApiResponseList configParamsList = null;
			try {
				configParamsList = (ApiResponseList) api.getAuthenticationCredentialsConfigParams(contextId);
			} catch (ClientApiException e) {

				e.printStackTrace();
				listener.error(ExceptionUtils.getStackTrace(e));
			}

			StringBuilder sb = new StringBuilder("Users' config params: ");
			for (ApiResponse r : configParamsList.getItems()) {
				ApiResponseSet set = (ApiResponseSet) r;
				sb.append(set.getAttribute("name")).append(" (");
				sb.append((set.getAttribute("mandatory").equals("true") ? "mandatory" : "optional"));
				sb.append("), ");
			}

			listener.getLogger().println(sb.deleteCharAt(sb.length() - 2).toString());
		}
	}

	private static String extractUserId(ApiResponse response) {
		return ((ApiResponseElement) response).getValue();
	}

	/****************************
	 * SCRIPTS VIEW
	 ***********************************************************/
	public String getScripts() {

		ApiResponseList configParamsList;
		StringBuilder sb = new StringBuilder();
		try {
			configParamsList = (ApiResponseList) api.listScripts();

			for (ApiResponse r : configParamsList.getItems()) {
				ApiResponseSet set = (ApiResponseSet) r;
				sb.append(set.getAttribute("name") + "\n");

			}

		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));

		}

		return sb.toString();
	}

	/****************************
	 * HOME DIRECTORY
	 ***********************************************************/

	public String getZapHomeDirectory() {

		ApiResponseElement set = null;
		try {
			set = (ApiResponseElement) api.getZAPHomeDirectory();

		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
		return set.getValue();
	}

	/****************************
	 * CONTEXT CONFIG
	 ***********************************************************/

	public String getContextId(String contextname, BuildListener listener) {

		try {

			ApiResponseSet set = (ApiResponseSet) api.context(contextname);
			return set.getAttribute("id");

		} catch (ClientApiException e) {

			System.out.println("Context dose not exist\nIt will be created...");
			listener.getLogger().println("Context dose not exist\nIt will be created...");

			try {
				api.newContext(zapProxyKey, contextname);
				System.out.println("Context created...");
				listener.getLogger().println("Context created...");
				return getContextId(contextname, listener);
			} catch (ClientApiException e1) {

				e1.printStackTrace();
				listener.error(ExceptionUtils.getStackTrace(e1));
			}

		}
		return null;
	}

	public String getUserId(String contextid, BuildListener listener) throws ClientApiException {

		ApiResponseList userParamsList = (ApiResponseList) api.usersList(contextid);
		String userId = null;
		StringBuilder sb = new StringBuilder("Users' config params: \n");

		for (ApiResponse r : userParamsList.getItems()) {
			ApiResponseSet set = (ApiResponseSet) r;
			userId = set.getAttribute("id");
			sb.append("id=" + set.getAttribute("id"));
			sb.append("\n");

			sb.append("enabled=" + set.getAttribute("enabled"));
			sb.append("\n");

			sb.append("contextId=" + set.getAttribute("contextId"));
			sb.append("\n");

			sb.append("name=" + set.getAttribute("name"));
			sb.append("\n");
			sb.append("/************************/");

		}
		listener.getLogger().println(sb);
		return userId;

	}

	/****************************
	 * AUTHENTICATION CONFIG
	 ******************************************************/

	/**
	 * permet de spécifier le pattern permettant à ZAP de s'assurer que
	 * l'utilisateur est bien authentifié
	 * 
	 * @param api
	 * @param contextId
	 * @throws UnsupportedEncodingException
	 * @throws ClientApiException
	 */

	public void setLoggedInIndicator(String contextId, String loggedInIndicator, BuildListener listener) {

		try {
			api.setLoggedInIndicator(zapProxyKey, contextId, loggedInIndicator);
			listener.getLogger().println("Configured logged in indicator regex: "
					+ ((ApiResponseElement) api.getLoggedInIndicator(contextId)).getValue());
		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	/**
	 * permet de définir le pattern permettant à ZAP de savoir que l'utilisateur
	 * n'est pas (plus) authentiifé
	 * 
	 * @param api
	 * @param contextId
	 * @throws UnsupportedEncodingException
	 * @throws ClientApiException
	 */
	public void setLoggedOutIndicator(String contextId, String loggedOutIndicator, BuildListener listener) {

		try {
			api.setLoggedOutIndicator(zapProxyKey, contextId, loggedOutIndicator);
			listener.getLogger().println("Configured logged Out indicator regex: "
					+ ((ApiResponseElement) api.getLoggedOutIndicator(contextId)).getValue());

		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	/**
	 * permet de définir les paramètres d'authentification
	 * 
	 * @param api
	 * @param contextId
	 * @return
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException
	 */
	public void setUpFormBasedAuthentication(String contextId, String loginUrl, String loginRequestData,
			String usernameParameter, String passwordParameter, BuildListener listener) {

		StringBuilder formBasedConfig = new StringBuilder();
		
		//debug
		StringBuilder formBasedConfigWithoutPassword = new StringBuilder();
		String loginRequestDataWithoutPassword=loginRequestData;
		
		try {
			formBasedConfig.append("loginUrl=").append(URLEncoder.encode(loginUrl, "UTF-8"));			

			loginRequestData = usernameParameter + "={%username%}&" + passwordParameter + "={%password%}&"	+ loginRequestData;
			formBasedConfig.append("&loginRequestData=").append(URLEncoder.encode(loginRequestData, "UTF-8"));

			api.setAuthenticationMethod(zapProxyKey, contextId, "formBasedAuthentication", formBasedConfig.toString());			
			
			//debug			
			formBasedConfigWithoutPassword.append("loginUrl=").append(URLEncoder.encode(loginUrl, "UTF-8"));
			loginRequestDataWithoutPassword = usernameParameter + "={%username%}&" + passwordParameter + "=xxxxxxxxxxxxx&"
					+ loginRequestDataWithoutPassword;
			formBasedConfigWithoutPassword.append("&loginRequestData=").append(URLEncoder.encode(loginRequestDataWithoutPassword, "UTF-8"));
			

			listener.getLogger().println("Setting form based authentication configuration as: " + formBasedConfigWithoutPassword.toString());
			if(debug == true)
			listener.getLogger().println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));	
			

		} catch (UnsupportedEncodingException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void setScriptBasedAuthentication(String contextId, String scriptName, BuildListener listener) {

		StringBuilder scriptBasedConfig = new StringBuilder();
		try {
			scriptBasedConfig.append("scriptName=").append(URLEncoder.encode(scriptName, "UTF-8"));
			
			listener.getLogger().println("Setting Script based authentication configuration as: " + scriptBasedConfig.toString());
			api.setAuthenticationMethod(zapProxyKey, contextId, "scriptBasedAuthentication",scriptBasedConfig.toString());

			if(debug == true)
			listener.getLogger().println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));

		} catch (UnsupportedEncodingException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void setHttpBasedAuthentication(String contextId, String hostname,String realm, int httpAuthenticationPort,BuildListener listener) {

		StringBuilder httpBasedConfig = new StringBuilder();
		String port = String.valueOf(httpAuthenticationPort);
		try {
			httpBasedConfig.append("hostname=").append(URLEncoder.encode(hostname, "UTF-8"));
			httpBasedConfig.append("&realm=").append(URLEncoder.encode(realm, "UTF-8"));
			httpBasedConfig.append("&port=").append(URLEncoder.encode(port, "UTF-8"));
			
			listener.getLogger().println("Setting HTTP based authentication configuration as: " + httpBasedConfig.toString());
			api.setAuthenticationMethod(zapProxyKey, contextId, "httpAuthentication",httpBasedConfig.toString());

			if(debug == true)
			listener.getLogger().println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));

		} catch (UnsupportedEncodingException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}
//	public void setScriptBasedAuthentication(String contextId, String LoginUrl, String postData, String Cookie,
//			String scriptName, BuildListener listener) {
//
//		StringBuilder scriptBasedConfig = new StringBuilder();
//		try {
//			scriptBasedConfig.append("scriptName=").append(URLEncoder.encode(scriptName, "UTF-8"));
//			scriptBasedConfig.append("&LoginUrl=").append(URLEncoder.encode(LoginUrl, "UTF-8"));
//			scriptBasedConfig.append("&postData=").append(URLEncoder.encode(postData, "UTF-8"));
//			scriptBasedConfig.append("&Cookie=").append(URLEncoder.encode(Cookie, "UTF-8"));
//			listener.getLogger()
//					.println("Setting Script based authentication configuration as: " + scriptBasedConfig.toString());
//			api.setAuthenticationMethod(zapProxyKey, contextId, "scriptBasedAuthentication",
//					scriptBasedConfig.toString());
//			if(debug == true)
//			listener.getLogger().println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));
//
//		} catch (UnsupportedEncodingException e) {
//			e.printStackTrace();
//			listener.error(ExceptionUtils.getStackTrace(e));
//		} catch (ClientApiException e) {
//
//			e.printStackTrace();
//			listener.error(ExceptionUtils.getStackTrace(e));
//		}
//
//	}

	/**
	 * permet de spécifier les données d'authentification liées à l'utilisateur
	 * (cas : script d'authentification)
	 * 
	 * @param api
	 * @param contextId
	 * @param user
	 *            nom de l'utilisateur utilisé dans le test
	 * @param username
	 * @param password
	 * @return
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException
	 */
	public String setUserScriptAuthConfig(String contextId, String user, String username, String password,
			BuildListener listener) {

		String userId = null;
		StringBuilder userAuthConfig = new StringBuilder();
		StringBuilder userAuthConfigWithoutPassword = new StringBuilder();
		
		
		try {
			userId = extractUserId(api.newUser(zapProxyKey, contextId, user));
			
			
			userAuthConfig.append("Username=").append(URLEncoder.encode(username, "UTF-8"));
			userAuthConfig.append("&Password=").append(URLEncoder.encode(password, "UTF-8"));
			//debug
			userAuthConfigWithoutPassword.append("Username=").append(URLEncoder.encode(username, "UTF-8"));
			userAuthConfigWithoutPassword.append("&Password=").append(URLEncoder.encode("xxxxxx", "UTF-8"));			
			listener.getLogger().println("Setting user authentication configuration as: " + userAuthConfigWithoutPassword.toString());
			
			
			api.setAuthenticationCredentials(zapProxyKey, contextId, userId, userAuthConfig.toString());
			if(debug == true)
			listener.getLogger().println("Authentication config: " + api.getUserById(contextId, userId).toString(0));
			
			
			
			
			
		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (UnsupportedEncodingException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return userId;
	}

	/**
	 * permet de spécifier les données d'authentification liées à l'utilisateur
	 * (cas : script d'authentification)
	 * 
	 * @param api
	 * @param contextId
	 * @param user
	 *            nom de l'utilisateur utilisé dans le test
	 * @param username
	 * @param password
	 * @return
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException
	 */
	public String setUserFormAuthConfig(String contextId, String user, String username, String password,
			BuildListener listener) {

		String userId = null;
		StringBuilder userAuthConfig = new StringBuilder();
		StringBuilder userAuthConfigWithoutPassword = new StringBuilder();
		try {
			userId = extractUserId(api.newUser(zapProxyKey, contextId, user));
			
			userAuthConfig.append("username=").append(URLEncoder.encode(username, "UTF-8"));
			userAuthConfig.append("&password=").append(URLEncoder.encode(password, "UTF-8"));
			
			//debug
			userAuthConfigWithoutPassword.append("username=").append(URLEncoder.encode(username, "UTF-8"));
			userAuthConfigWithoutPassword.append("&password=").append(URLEncoder.encode("xxxxx", "UTF-8"));			
			listener.getLogger().println("Setting user authentication configuration as: " + userAuthConfigWithoutPassword.toString());
			
			
			api.setAuthenticationCredentials(zapProxyKey, contextId, userId, userAuthConfig.toString());
			if(debug == true)
				listener.getLogger().println("Authentication config: " + api.getUserById(contextId, userId).toString(0));
		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (UnsupportedEncodingException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return userId;
	}

	/**
	 * set up user for the context and enable user
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @param username user name to be used in authentication
	 * @param password password for the authentication user
	 * @param contextId id of the created context
	 * @return userId id of the newly setup user
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException 
	 */
	public String setUpUser(BuildListener listener,  String username,
						String password, String contextId)   {

		String userIdTemp = null;
		// add new user and authentication details
		// Make sure we have at least one user
		// extract user id 
		try {
			userIdTemp = extractUserId(api.newUser(zapProxyKey, contextId, username));
			
			// Prepare the configuration in a format similar to how URL parameters are formed. This
			// means that any value we add for the configuration values has to be URL encoded.
			StringBuilder userAuthConfig = new StringBuilder();
			userAuthConfig.append("username=").append(URLEncoder.encode(username, "UTF-8"));
			userAuthConfig.append("&password=").append(URLEncoder.encode(password, "UTF-8"));
			String authCon=userAuthConfig.toString();
			
			api.setAuthenticationCredentials(zapProxyKey, contextId, userIdTemp, authCon);

			listener.getLogger().println("New user added. username :" +username);
			
			api.setUserEnabled(zapProxyKey, contextId,userIdTemp,"true");
			listener.getLogger().println("User : "+username+" is now Enabled");
			
			//to make spidering and ajax spidering in authentication mod
			setUpForcedUser(listener,  contextId,  userIdTemp) ;
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}



		return userIdTemp;
	}
	/**
	 * set up forced user for the context and enable user, this help to make spidering and ajax spidering as authenticated user
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @param contextId id of the created context
	 * @return userId id of the newly setup user
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException 
	 */
	private void setUpForcedUser(BuildListener listener, String contextid, String userid) 
						throws ClientApiException, UnsupportedEncodingException {
		
		api.setForcedUser(zapProxyKey, contextid,userid);
		api.setForcedUserModeEnabled(zapProxyKey, true);
		

	}
	
	/**
	 * permet d'inclure une url dans un contexte
	 * 
	 * @param api
	 * @param url
	 */
	public void includeInContext(String url, String contextname, BuildListener listener) {
		try {
			String[] urls = url.split("\n");

			for (int i = 0; i < urls.length; i++) {
				urls[i] = urls[i].trim();
				if (!urls[i].isEmpty()) {
					ApiResponse status = api.includeInContext(zapProxyKey, contextname, urls[i]);
					 
						if (debug == true)
							listener.getLogger().println(((ApiResponseElement) status).getValue());
				}

			}

		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	/**
	 * permet d'inclure une url dans un contexte
	 * 
	 * @param api
	 * @param url
	 */
	public void excludeFromContext(String url, String contextname, BuildListener listener) {

		try {

			String[] urls = url.split("\n");

			for (int i = 0; i < urls.length; i++) {
				urls[i] = urls[i].trim();
				if (!urls[i].isEmpty()) {
					ApiResponse status = api.excludeFromContext(zapProxyKey, contextname, urls[i]);
					if (debug == true)
						listener.getLogger().println(((ApiResponseElement) status).getValue());
				}

			}

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}
	
	/**
	 * permet d'inclure une url dans un contexte
	 * 
	 * @param api
	 * @param url
	 */
	public void excludeFromSpider(String urlRegex, BuildListener listener) {

		try {

			String[] urls = urlRegex.split("\n");

			for (int i = 0; i < urls.length; i++) {
				urls[i] = urls[i].trim();
				if (!urls[i].isEmpty()) {
					ApiResponse status = api.excludeFromSpider(zapProxyKey, urls[i]);
					if (debug == true)
						listener.getLogger().println(((ApiResponseElement) status).getValue());
				}

			}

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	/**
	 * permet d'inclure une url dans un contexte
	 * 
	 * @param api
	 * @param url
	 */
	public void excludeFromActifScan(String urlRegex, BuildListener listener) {

		try {

			String[] urls = urlRegex.split("\n");

			for (int i = 0; i < urls.length; i++) {
				urls[i] = urls[i].trim();
				if (!urls[i].isEmpty()) {
					ApiResponse status = api.excludeFromActifScan(zapProxyKey, urls[i]);
					if (debug == true)
						listener.getLogger().println(((ApiResponseElement) status).getValue());
				}

			}

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}
	public void enableUser(String contextid, String userid, BuildListener listener) {

		try {
			ApiResponse status = api.setUserEnabled(zapProxyKey, contextid, userid, "true");
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
	}
	
	
	/**
	 * 
	 * @param contextId
	 * @param ruleId
	 * @param url
	 * @param parameter
	 * @param urlIsRegex
	 */
	public void addAlertFilter(String contextId, String ruleId, String url, String parameter ){
		String newLevel="-1";
		 String enabled="true";
		 String urlIsRegex="false";
		
		try {
			ApiResponse status = api.addAlertFilter(zapProxyKey, contextId, ruleId, url, parameter,  newLevel, urlIsRegex, enabled) ;
				if (debug == true)
					listener.getLogger().println(((ApiResponseElement) status).getValue());

			} catch (ClientApiException e) {
				e.printStackTrace();
				listener.error(ExceptionUtils.getStackTrace(e));
			}
			
	}
	
	
	

	public static void setWebProxyDetails(String webProxyHost, int webProxyPort, String webProxyUser,
			String webProxyPassword) {

		System.setProperty("http.proxyHost", webProxyHost);
		System.setProperty("http.proxyPort", String.valueOf(webProxyPort));
		Authenticator.setDefault(new ProxyAuthenticator(webProxyUser, webProxyPassword));
	}

	/*****************************
	 * GENERAl CONFIG
	 ********************************/

	public ApiResponse setPolicyAttackStrength(String id, String attackstrength, String scanpolicyname) {

		try {
			return api.setPolicyAttackStrength(zapProxyKey, id, attackstrength, scanpolicyname);
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return null;
	}

	public ApiResponse setScannerAttackStrength(String id, String attackstrength, String scanpolicyname) {

		try {
			return api.setScannerAttackStrength(zapProxyKey, id, attackstrength, scanpolicyname);
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return null;
	}

	public ApiResponse setPolicyAlertThreshold(String id, String attackstrength, String scanpolicyname) {

		try {
			api.setPolicyAlertThreshold(zapProxyKey, id, attackstrength, scanpolicyname);
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return null;
	}

	public ApiResponse setScannerAlertThreshold(String id, String attackstrength, String scanpolicyname) {

		try {
			api.setScannerAlertThreshold(zapProxyKey, id, attackstrength, scanpolicyname);
		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return null;
	}

	/**************************** SESSION *******************************/
	/**
	 * Loads the session with the given name. If a relative path is specified it
	 * will be resolved against the "session" directory in ZAP "home" dir.
	 */
	public ApiResponse loadSession(String name) {

		try {
			return api.loadSession(zapProxyKey, name);
		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
		return null;
	}

	public String saveSession(String name, String overwrite, BuildListener listener) {

		try {
			ApiResponse status = api.saveSession(zapProxyKey, name, overwrite);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

			return ((ApiResponseElement) status).getValue();

		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));

		}
		return "KO";
	}

	/**
	 * Creates a new session, optionally overwriting existing files. If a
	 * relative path is specified it will be resolved against the "session"
	 * directory in ZAP "home" dir.
	 */
	public String newSession(String name, String overwrite, BuildListener listener) {
		try {
			ApiResponse status = api.newSession(zapProxyKey, name, overwrite);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

			return ((ApiResponseElement) status).getValue();

		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));

		}
		return "KO";

	}

	/**************************************************************************/

	public ApiResponse setOptionPostForm(boolean bool) {

		try {
			return api.setOptionPostForm(zapProxyKey, bool);
		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
		return null;
	}

	public ApiResponse setOptionProcessForm(boolean bool) {

		try {
			return api.setOptionProcessForm(zapProxyKey, bool);
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
		return null;
	}

	public ApiResponse setOptionHandleODataParametersVisited(boolean bool) {

		try {
			return api.setOptionHandleODataParametersVisited(zapProxyKey, bool);
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
		return null;
	}

	public ApiResponse setOptionShowAdvancedDialog(boolean bool) {

		try {
			return api.setOptionShowAdvancedDialog(zapProxyKey, bool);
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
		return null;
	}

	public ApiResponse setOptionParseComments(boolean bool) {

		try {
			return api.setOptionParseComments(zapProxyKey, bool);
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
		return null;
	}

	public ApiResponse setOptionParseRobotsTxt(boolean bool) {

		try {
			return api.setOptionParseRobotsTxt(zapProxyKey, bool);
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
		return null;
	}

	public ApiResponse setOptionParseSitemapXml(boolean bool) {
		try {
			return api.setOptionParseSitemapXml(zapProxyKey, bool);
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}
		return null;
	}

	/**
	 * List context names of current session
	 */
	public String getContextList() {

		ApiResponse response = null;
		try {
			response = api.contextList();
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return ((ApiResponseElement) response).getValue();

	}

	/**
	 * List context names of current session
	 */
	public static String getContextList(CustomZapApi api, BuildListener listener) {

		ApiResponse response = null;
		try {
			response = api.contextList();
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return ((ApiResponseElement) response).getValue();

	}

	/*************************************************** Spidering ******************************************************************/

	/**
	 * phase de spidering en mode authentifié
	 * 
	 * @param api
	 * @param url
	 * @param contextid
	 * @param userid
	 * @param maxchildren
	 * @return
	 * @throws ClientApiException
	 * @throws InterruptedException
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 */
	public String spiderAsUserURL(String url, String contextid, String userid, String maxchildren,
			BuildListener listener) {

		ApiResponse status;
		String scanid = null;
		try {
			status = api.spiderAsUser(zapProxyKey, url, contextid, userid, maxchildren);
			scanid = ((ApiResponseElement) status).getValue();
			Map<String, String> params2 = new HashMap<String, String>();
			params2.put("scanid", scanid);
			int progress;

			while (true) {
				Thread.sleep(1000);
				status = api.spiderStatus(params2);
				progress = Integer.parseInt(((ApiResponseElement) status).getValue());
				listener.getLogger().println("Spider progress : " + progress + "%");
				if (progress >= 100) {
					break;
				}
			}

			listener.getLogger().println("Spider complete");

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (InterruptedException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return scanid;
	}

	/**
	 * 
	 * @param proxyRequired
	 * @param api
	 * @param url
	 * @param contextid
	 * @param userid
	 * @param maxchildren
	 * @return
	 * @throws ClientApiException
	 * @throws InterruptedException
	 * @throws IOException
	 * @throws ParserConfigurationException
	 * @throws SAXException
	 */
	public String spiderURL(String url, String maxchildren, BuildListener listener) {

		ApiResponse status;
		String scanid = null;
		try {
			status = api.spider(zapProxyKey, url, maxchildren);
			scanid = ((ApiResponseElement) status).getValue();
			Map<String, String> params2 = new HashMap<String, String>();
			params2.put("scanid", scanid);
			int progress;

			while (true) {
				Thread.sleep(1000);
				status = api.spiderStatus(params2);
				progress = Integer.parseInt(((ApiResponseElement) status).getValue());
				listener.getLogger().println("Spider progress : " + progress + "%");
				if (progress >= 100) {
					break;
				}
			}
			listener.getLogger().println("Spider complete");

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (InterruptedException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return scanid;
	}

	public String ajaxSpiderURL(String url, String inscope, BuildListener listener) {
		// String result, METHOD, URL;
		// String[] splitedResult, header;
		ApiResponse status;
		String scanid = null;
		try {
			status = api.ajaxScan(zapProxyKey, url, inscope);
			scanid = ((ApiResponseElement) status).getValue();
			String progress;

			while (true) {
				Thread.sleep(2500);
				status = api.ajaxStatus();
				progress = ((ApiResponseElement) status).getValue();
				listener.getLogger().println("Ajax Spider progress : " + progress);
				String nbrOfResults = ((ApiResponseElement) api.ajaxNumberOfResults()).getValue();
				listener.getLogger().println("Number of results : " + nbrOfResults);
				if (!progress.equals("running")) {
					break;
				}
			}
			listener.getLogger().println("Ajax Spidering complete");
			// listener.getLogger().println("***************************************
			// Liste des URLS trouvées
			// ***************************************");
			// String nbrOfResults = ((ApiResponseElement)
			// api.ajaxNumberOfResults()).getValue();
			// listener.getLogger().println("Ajax Spidering number of results :
			// " + nbrOfResults);
			// ApiResponseList results = (ApiResponseList) (api.ajaxResults("1",
			// String.valueOf(nbrOfResults)));
			//
			// for (ApiResponse r : results.getItems()) {
			// result = ((ApiResponseSet) r).getAttribute("requestHeader");
			// splitedResult = result.split("\n");
			// header = (splitedResult[0]).split(" ");
			// METHOD = header[0];
			// URL = header[1];
			// listener.getLogger().println(METHOD + " : " + URL);
			// listener.getLogger().println("*********************************************************************************************************");
			//
			// }

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (InterruptedException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

		return scanid;
	}

	/**
	 * Affiche les résultats de la phase spidering
	 * 
	 * @param api
	 * @param scanId
	 */
	public void viewSpiderResults(String scanId, BuildListener listener) {

		try {
			ApiResponseList results = (ApiResponseList) api.results(scanId);

			listener.getLogger().println("------------------- DEBUT : RESULTATS DU SPIDERING ------------------- ");

			for (ApiResponse r : results.getItems()) {
				listener.getLogger().println(((ApiResponseElement) r).getValue());
			}
			listener.getLogger().println("------------------- FIN : RESULTATS DU SPIDERING ------------------- ");

		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}
	
	/**
	 * Affiche les résultats de la phase spidering
	 * 
	 * @param api
	 * @param scanId
	 */
	public void logSpiderResults(String scanId, FilePath workspace,String zapHomeDirectory,String ROOT_PATH, String LOGS_PATH, String SPIDERING_RESULTS_FILE ) {
		
		String FILE_SEPARATOR;
		
		if (zapHomeDirectory.startsWith("/")) {
			FILE_SEPARATOR = "/";
		} else {
			FILE_SEPARATOR = "\\";
		}

		/* ======================================================= */

		StringBuilder sb = new StringBuilder();	

		// probleme avec getFILE_SEPARATOR(), avant le build cette
		// fonction doit retourner une valeur
		String filePth = ROOT_PATH + FILE_SEPARATOR + LOGS_PATH + FILE_SEPARATOR+ SPIDERING_RESULTS_FILE;
		
		try {
			ApiResponseList results = (ApiResponseList) api.results(scanId);

			//listener.getLogger().println("------------------- DEBUT : RESULTATS DU SPIDERING ------------------- ");
			sb.append("------------------- DEBUT : RESULTATS DU SPIDERING ------------------- \n\n");
			

			for (ApiResponse r : results.getItems()) {
				//listener.getLogger().println(((ApiResponseElement) r).getValue());
				sb.append(((ApiResponseElement) r).getValue()+"\n");
			}
			//listener.getLogger().println("------------------- FIN : RESULTATS DU SPIDERING ------------------- ");
			sb.append("\n------------------- FIN : RESULTATS DU SPIDERING ------------------- \n");
			
			
			String spideringResults = sb.toString();
			
			if (workspace != null) {
				File spideringResultsFile = new File(workspace.getRemote(), filePth);
				FileUtils.writeByteArrayToFile(spideringResultsFile, spideringResults.getBytes());
			
			}

		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/**
	 * Affiche les résultats de la phase spidering
	 * 
	 * @param api
	 * @param scanId
	 */
	public void viewAjaxSpiderResults(BuildListener listener) {

		String result, METHOD, URL;
		String[] splitedResult, header;
		ArrayList<String> list = new ArrayList<String>();
		Set<String> set = new HashSet<String>();

		listener.getLogger().println("------------------- DEBUT : RESULTATS DE L'AJAX SPIDERING ------------------- ");
		String nbrOfResults;
		try {
			nbrOfResults = ((ApiResponseElement) api.ajaxNumberOfResults()).getValue();

			listener.getLogger().println("Ajax Spidering number of results : " + nbrOfResults);
			ApiResponseList results = (ApiResponseList) (api.ajaxResults("1", String.valueOf(nbrOfResults)));

			for (ApiResponse r : results.getItems()) {
				result = ((ApiResponseSet) r).getAttribute("requestHeader");
				splitedResult = result.split("\n");
				header = (splitedResult[0]).split(" ");
				METHOD = header[0];
				URL = header[1];
				list.add(URL);
				// listener.getLogger().println(METHOD + " : " + URL);
			}

			set.addAll(list);
			ArrayList<String> distinctList = new ArrayList<String>(set);

			Iterator<String> it = distinctList.iterator();
			while (it.hasNext()) {
				listener.getLogger().println(it.next());
			}

			listener.getLogger()
					.println("------------------- FIN : RESULTATS DE L'AJAX SPIDERING ------------------- ");

		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	
	/**
	 * Affiche les résultats de la phase spidering
	 * 
	 * @param api
	 * @param scanId
	 */
	public void logAjaxSpiderResults(FilePath workspace,String zapHomeDirectory,String ROOT_PATH, String LOGS_PATH, String AJAX_SPIDERING_RESULTS_FILE ) {
		
		String FILE_SEPARATOR;
		String result, METHOD, URL;
		String[] splitedResult, header;
		ArrayList<String> list = new ArrayList<String>();
		Set<String> set = new HashSet<String>();
		StringBuilder sb = new StringBuilder();	
		String nbrOfResults;
		
		if (zapHomeDirectory.startsWith("/")) {
			FILE_SEPARATOR = "/";
		} else {
			FILE_SEPARATOR = "\\";
		}

		/* ======================================================= */

		

		// probleme avec getFILE_SEPARATOR(), avant le build cette
		// fonction doit retourner une valeur
		String filePth = ROOT_PATH + FILE_SEPARATOR + LOGS_PATH + FILE_SEPARATOR+ AJAX_SPIDERING_RESULTS_FILE;
		
		try {
		
			//listener.getLogger().println("------------------- DEBUT : RESULTATS DU SPIDERING ------------------- ");
			sb.append("------------------- DEBUT : RESULTATS DE L'AJAX SPIDERING ------------------- \n\n");
			
			nbrOfResults = ((ApiResponseElement) api.ajaxNumberOfResults()).getValue();

			//listener.getLogger().println("Ajax Spidering number of results : " + nbrOfResults);
			ApiResponseList results = (ApiResponseList) (api.ajaxResults("1", String.valueOf(nbrOfResults)));

			for (ApiResponse r : results.getItems()) {
				result = ((ApiResponseSet) r).getAttribute("requestHeader");
				splitedResult = result.split("\n");
				header = (splitedResult[0]).split(" ");
				METHOD = header[0];
				URL = header[1];
				list.add(URL);
				// listener.getLogger().println(METHOD + " : " + URL);
			}

			set.addAll(list);
			ArrayList<String> distinctList = new ArrayList<String>(set);

			Iterator<String> it = distinctList.iterator();
			while (it.hasNext()) {
				//listener.getLogger().println(it.next());
				sb.append(it.next()+"\n");
			}

			
			

			//listener.getLogger().println("------------------- FIN : RESULTATS DU SPIDERING ------------------- ");
			sb.append("\n------------------- FIN : RESULTATS DE L'AJAX SPIDERING ------------------- \n");
			
			
			String spideringResults = sb.toString();
			
			if (workspace != null) {
				File spideringResultsFile = new File(workspace.getRemote(), filePth);
				FileUtils.writeByteArrayToFile(spideringResultsFile, spideringResults.getBytes());
			
			}

		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	/*******************************************************************************************************************************/

	/*************************************************** Scanning ******************************************************************/
	public void scanURL(String url, String scanid, String scanPolicyName, BuildListener listener) {

		Map<String, String> params = new HashMap<String, String>();
		params.put("apikey", zapProxyKey);
		params.put("recurse", "true");
		params.put("scanPolicyName", scanPolicyName);
		params.put("inScopeOnly", "false");
		params.put("url", url);
		ApiResponse status;
		try {
			status = api.scan(params);
			int progress;

			Map<String, String> params2 = new HashMap<String, String>();
			params2.put("scanid", scanid);
			while (true) {
				Thread.sleep(5000);
				status = api.scanStatus(params2);
				progress = Integer.parseInt(((ApiResponseElement) status).getValue());
				listener.getLogger().println("Active Scan progress : " + progress + "%");

				if (progress >= 100) {
					break;
				}
			}
			listener.getLogger().println("Active Scan complete");
			String nbrAlerts = api.numberOfAlerts("").toString(2);
			listener.getLogger().println("Alerts number = " + nbrAlerts);

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (InterruptedException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void scanURLAsUser(String url, String scanid, String contextid, String userid, String recurse,
			String ScanPolicyName, BuildListener listener) {
		ApiResponse status;
		try {
			status = api.scanAsUser(zapProxyKey, url, contextid, userid, recurse, ScanPolicyName);
			int progress;

			Map<String, String> params2 = new HashMap<String, String>();
			params2.put("scanid", scanid);
			while (true) {
				Thread.sleep(5000);
				status = api.scanStatus(params2);
				progress = Integer.parseInt(((ApiResponseElement) status).getValue());
				listener.getLogger().println("Active Scan progress : " + progress + "%");

				if (progress >= 100) {
					break;
				}
			}

			listener.getLogger().println("Active Scan complete");
			String nbrAlerts = api.numberOfAlerts("").toString(2);
			listener.getLogger().println("Alerts number = " + nbrAlerts);

		} catch (ClientApiException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		}

	}

	/*******************************************************************************************************************************/
	/**
	 * Generates a report in XML format
	 */
	public byte[] generateXmlReport() throws ClientApiException {
		return api.xmlreport(zapProxyKey);
	}

	/**
	 * Generates a report in HTML format
	 */
	public byte[] generateHtmlReport() throws ClientApiException {
		return api.htmlreport(zapProxyKey);
	}

	/*************************************************** Reporting ******************************************************************/
	public void saveReport(String xmlReportPath, BuildListener listener) {

		byte[] xmlReportBytes;
		try {
			xmlReportBytes = api.xmlreport(zapProxyKey);
			Files.write(Paths.get(xmlReportPath), xmlReportBytes);
			listener.getLogger().println("File [" + new File(xmlReportPath).getAbsolutePath() + "] saved");

		} catch (ClientApiException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (IOException e) {

			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	/****************************
	 * ForcedUser.java
	 ****************************************************/

	public void isForcedUserModeEnabled(BuildListener listener) {

		ApiResponse status;
		try {
			status = api.isForcedUserModeEnabled();
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void getForcedUser(String contextid, BuildListener listener) {
		ApiResponse status;
		try {
			status = api.getForcedUser(contextid);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void setForcedUser(String contextid, String userid, BuildListener listener) {

		ApiResponse status;
		try {
			status = api.setForcedUser(zapProxyKey, contextid, userid);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void setForcedUserModeEnabled(boolean bool, BuildListener listener) {

		ApiResponse status;
		try {
			status = api.setForcedUserModeEnabled(zapProxyKey, bool);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());
		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	/*******************************************************************************************************************************/

	public void enableAllScanners(String scanpolicyname, BuildListener listener) {
		try {
			ApiResponse status = api.enableAllScanners(zapProxyKey, scanpolicyname);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void disableAllScanners(String scanpolicyname, BuildListener listener) {

		try {
			ApiResponse status = api.disableAllScanners(zapProxyKey, scanpolicyname);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void enableScanners(String ids, BuildListener listener) {

		try {
			ApiResponse status = api.enableScanners(zapProxyKey, ids);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void disableScanners(String ids, BuildListener listener) {

		try {
			ApiResponse status = api.disableScanners(zapProxyKey, ids);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void setEnabledPolicies(String ids, BuildListener listener) {

		try {
			ApiResponse status = api.setEnabledPolicies(zapProxyKey, ids);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void PassiveScanEnableAllScanner(BuildListener listener) {

		try {
			ApiResponse status = api.PsEnableAllScanners(zapProxyKey);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void PassiveScanDisableAllScanner(BuildListener listener) {

		try {
			ApiResponse status = api.PsDisableAllScanners(zapProxyKey);
			if (debug == true)
				listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	/**
	 * Shuts down ZAP
	 * 
	 * @throws ClientApiException
	 */
	public void stopZap(String apikey, BuildListener listener) throws ClientApiException {

		ApiResponse status = api.shutdown(zapProxyKey);
		if (debug == true)
			listener.getLogger().println(((ApiResponseElement) status).getValue());

	}

}
