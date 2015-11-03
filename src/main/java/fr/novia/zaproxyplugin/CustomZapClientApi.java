
package fr.novia.zaproxyplugin;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.Proxy;
import java.net.URL;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseFactory;
import org.zaproxy.clientapi.core.ClientApiException;

import fr.novia.zaproxyplugin.utilities.PropertyLoader;
import fr.novia.zaproxyplugin.utilities.ProxyAuthenticator;
import hudson.model.BuildListener;

import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;

public class CustomZapClientApi implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3961600153488729709L;
	private static final int MILLISECONDS_IN_SECOND = 1000;
	private final String zapProxyKey;
	public final CustomZapApi api;
	private  final boolean  debug;

	private BuildListener listener;

	/*******************************************
	 * Constructeurs de classe
	 *****************************************************/

	public CustomZapClientApi(String ZAP_ADDRESS, int zapProxyPort, String ZAP_API_KEY, BuildListener listener, boolean debug) {
		super();

		this.zapProxyKey = ZAP_API_KEY;
		this.listener = listener;
		this.debug=debug;

		this.api = new CustomZapApi(ZAP_ADDRESS, "" + zapProxyPort + "", listener, debug);
	}

	public CustomZapClientApi(String zapProxyHost, int zapProxyPort, String zapProxyKey, boolean debug) {
		// TODO Auto-generated constructor stub
		super();

		this.zapProxyKey = zapProxyKey;
		this.debug=debug;
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

		ApiResponseList configParamsList = null;
		try {
			configParamsList = (ApiResponseList) api.getAuthenticationCredentialsConfigParams(contextId);
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
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

	// public static String getScripts(CustomZapApi api){
	//
	//
	//
	//
	// ApiResponseList configParamsList = null;
	// StringBuilder sb =new StringBuilder();
	// try {
	// configParamsList = (ApiResponseList) api.listScripts();
	//
	// for (ApiResponse r : configParamsList.getItems()) {
	// ApiResponseSet set = (ApiResponseSet) r;
	// sb.append(set.getAttribute("name")+"\n") ;
	//
	// }
	// sb.append("scripts loaded correctly");
	//
	// } catch (ClientApiException e) {
	// // TODO Auto-generated catch block
	// e.printStackTrace();
	// sb.append("ERROR :
	// "+e.getMessage()+"||"+e.getDetail()+"||"+e.getCode()+"||");
	// }
	//
	// return sb.toString();
	// }

	// /**
	// * @return the listener
	// */
	// public BuildListener getListener() {
	// return listener;
	// }
	//
	//
	// /**
	// * @param listener the listener to set
	// */
	// public void setListener(BuildListener listener) {
	// this.listener = listener;
	// this.api.setListener(listener);
	// }

	/****************************
	 * HOME DIRECTORY
	 ***********************************************************/

	public String getZapHomeDirectory() {

		ApiResponseElement set = null;
		try {
			set = (ApiResponseElement) api.getZAPHomeDirectory();

		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
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
			// TODO Auto-generated catch block
			// System.out.println("Context dose not exist\nIt will be
			// created...");
			listener.getLogger().println("Context dose not exist\nIt will be created...");
			listener.error(ExceptionUtils.getStackTrace(e));
			try {
				api.newContext(zapProxyKey, contextname);
				// System.out.println("Context created...");
				listener.getLogger().println("Context created...");
				return getContextId(contextname, listener);
			} catch (ClientApiException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
				listener.error(ExceptionUtils.getStackTrace(e1));
			}
			// e.printStackTrace();
		}
		return null;
	}
	
	
	public String  getUserId(String contextid, BuildListener listener) throws ClientApiException {
		
		
		ApiResponseList userParamsList = (ApiResponseList) api.usersList(contextid);
		String userId = null;
		StringBuilder sb = new StringBuilder("Users' config params: \n");
		//{"usersList":[{"id":"0","enabled":"true","contextId":"2","name":"ZAP USER","credentials":{"username":"test","type":"UsernamePasswordAuthenticationCredentials","password":"test"}}]}
		for (ApiResponse r : userParamsList.getItems()) {
			ApiResponseSet set = (ApiResponseSet) r;
			userId=set.getAttribute("id");
			sb.append("id="+set.getAttribute("id"));
			sb.append("\n");
			
			sb.append("enabled="+set.getAttribute("enabled"));
			sb.append("\n");
			
			sb.append("contextId="+set.getAttribute("contextId"));
			sb.append("\n");
			
			sb.append("name="+set.getAttribute("name"));
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
		try {
			formBasedConfig.append("loginUrl=").append(URLEncoder.encode(loginUrl, "UTF-8"));
			formBasedConfig.append("&loginRequestData=").append(URLEncoder.encode(
					usernameParameter + "={%username%}&" + passwordParameter + "={%password%}&" + loginRequestData,
					"UTF-8"));
			listener.getLogger()
					.println("Setting form based authentication configuration as: " + formBasedConfig.toString());
			api.setAuthenticationMethod(zapProxyKey, contextId, "formBasedAuthentication", formBasedConfig.toString());
			listener.getLogger()
					.println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));

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
			listener.getLogger()
					.println("Setting Script based authentication configuration as: " + scriptBasedConfig.toString());
			api.setAuthenticationMethod(zapProxyKey, contextId, "scriptBasedAuthentication",
					scriptBasedConfig.toString());
					
			listener.getLogger()
					.println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));
			
		} catch (UnsupportedEncodingException e) {
			
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (ClientApiException e) {
			 
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void setScriptBasedAuthentication(String contextId, String LoginUrl, String postData, String Cookie,
			String scriptName, BuildListener listener) {

		StringBuilder scriptBasedConfig = new StringBuilder();
		try {
			scriptBasedConfig.append("scriptName=").append(URLEncoder.encode(scriptName, "UTF-8"));
			scriptBasedConfig.append("&LoginUrl=").append(URLEncoder.encode(LoginUrl, "UTF-8"));
			scriptBasedConfig.append("&postData=").append(URLEncoder.encode(postData, "UTF-8"));
			scriptBasedConfig.append("&Cookie=").append(URLEncoder.encode(Cookie, "UTF-8"));
			listener.getLogger()
					.println("Setting Script based authentication configuration as: " + scriptBasedConfig.toString());
			api.setAuthenticationMethod(zapProxyKey, contextId, "scriptBasedAuthentication",
					scriptBasedConfig.toString());
			listener.getLogger()
					.println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));


		} catch (UnsupportedEncodingException e) {		
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		} catch (ClientApiException e) {
		
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

//	/**
//	 * permet de définir les paramètres d'authentification
//	 * 
//	 * @param api
//	 * @param contextId
//	 * @param loginUrl
//	 * @param loginRequestData
//	 * @throws ClientApiException
//	 * @throws UnsupportedEncodingException
//	 */
//
//	private void setFormBasedAuthentication(String contextId, String loginUrl, String loginRequestData) {
//
//		StringBuilder formBasedConfig = new StringBuilder();
//		try {
//			formBasedConfig.append("loginUrl=").append(URLEncoder.encode(loginUrl, "UTF-8"));
//			formBasedConfig.append("&loginRequestData=").append(URLEncoder.encode(loginRequestData, "UTF-8"));
//			System.out.println("Setting form based authentication configuration as: " + formBasedConfig.toString());
//			api.setAuthenticationMethod(zapProxyKey, contextId, "formBasedAuthentication", formBasedConfig.toString());
//			System.out.println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));
//		
//		} catch (ClientApiException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (UnsupportedEncodingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
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
		try {
			userId = extractUserId(api.newUser(zapProxyKey, contextId, user));
			StringBuilder userAuthConfig = new StringBuilder();
			userAuthConfig.append("Username=").append(URLEncoder.encode(username, "UTF-8"));
			userAuthConfig.append("&Password=").append(URLEncoder.encode(password, "UTF-8"));
			listener.getLogger().println("Setting user authentication configuration as: " + userAuthConfig.toString());
			api.setAuthenticationCredentials(zapProxyKey, contextId, userId, userAuthConfig.toString());
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
		try {
			userId = extractUserId(api.newUser(zapProxyKey, contextId, user));
			StringBuilder userAuthConfig = new StringBuilder();
			userAuthConfig.append("username=").append(URLEncoder.encode(username, "UTF-8"));
			userAuthConfig.append("&password=").append(URLEncoder.encode(password, "UTF-8"));
			listener.getLogger().println("Setting user authentication configuration as: " + userAuthConfig.toString());
			api.setAuthenticationCredentials(zapProxyKey, contextId, userId, userAuthConfig.toString());
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
	 * permet d'inclure une url dans un contexte
	 * 
	 * @param api
	 * @param url
	 */
	public void includeInContext(String url, String contextname, BuildListener listener) {
		try {
			String[] urls = url.split("\n");
			listener.getLogger().println("URLS : " + urls.toString());

			for (int i = 0; i < urls.length; i++) {
				urls[i] = urls[i].trim();
				if (!urls[i].isEmpty()) {
					ApiResponse status = api.includeInContext(zapProxyKey, contextname, urls[i]);					
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
			listener.getLogger().println("URLS : " + urls.toString());

			for (int i = 0; i < urls.length; i++) {
				urls[i] = urls[i].trim();
				if (!urls[i].isEmpty()) {
					ApiResponse status = api.excludeFromContext(zapProxyKey, contextname, urls[i]);
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
			listener.getLogger().println(((ApiResponseElement) status).getValue());

			return ((ApiResponseElement) status).getValue();

		} catch (ClientApiException e) {
			 
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
			
		}
		return "KO";
	}
	
	/**
	 * Creates a new session, optionally overwriting existing files. If a relative path is specified it will be resolved against the "session" directory in ZAP "home" dir.
	 */
	public String newSession(String name, String overwrite, BuildListener listener)   {
		try {
		ApiResponse status = api.newSession(zapProxyKey, name, overwrite);
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
		String result, METHOD, URL;
		String[] splitedResult, header;		
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
			listener.getLogger().println("*************************************** Liste des URLS trouvées ***************************************");			
			String nbrOfResults = ((ApiResponseElement) api.ajaxNumberOfResults()).getValue();			
			listener.getLogger().println("Ajax Spidering number of results : " + nbrOfResults);
			ApiResponseList results = (ApiResponseList) (api.ajaxResults("1", String.valueOf(nbrOfResults)));

			for (ApiResponse r : results.getItems()) {
				result = ((ApiResponseSet) r).getAttribute("requestHeader");
				splitedResult = result.split("\n");
				header = (splitedResult[0]).split(" ");
				METHOD = header[0];
				URL = header[1];
				listener.getLogger().println(METHOD + " : " + URL);
				listener.getLogger().println("*********************************************************************************************************");

			}

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
			listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void disableAllScanners(String scanpolicyname, BuildListener listener) {

		try {
			ApiResponse status = api.disableAllScanners(zapProxyKey, scanpolicyname);
			listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {			
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void enableScanners(String ids, BuildListener listener) {

		try {
			ApiResponse status = api.enableScanners(zapProxyKey, ids);
			listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {			
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void disableScanners(String ids, BuildListener listener) {

		try {
			ApiResponse status = api.disableScanners(zapProxyKey, ids);
			listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {			
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void setEnabledPolicies(String ids, BuildListener listener) {

		try {
			ApiResponse status = api.setEnabledPolicies(zapProxyKey, ids);
			listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void PassiveScanEnableAllScanner(BuildListener listener) {

		try {
			ApiResponse status = api.PsEnableAllScanners(zapProxyKey);
			listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {			
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

	public void PassiveScanDisableAllScanner(BuildListener listener) {

		try {
			ApiResponse status = api.PsDisableAllScanners(zapProxyKey);
			listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

//	public void startZAPAsUser(String url, String contextid, String userid, String maxchildren, String ScanPolicyName,
//			BuildListener listener) {
//
//		System.out.println("######################### phase de spidering ######################### ");
//		String scanid = spiderAsUserURL(url, contextid, userid, maxchildren, listener);
//
//		System.out.println("######################### Résultats de spidering ######################### ");
//		viewSpiderResults(scanid, listener);
//		System.out.println("########################################################################## ");
//
//		// scan
//		System.out.println("######################### phase de scan ######################### ");
//		scanURLAsUser(url, scanid, contextid, userid, "true", ScanPolicyName, listener);
//
//		// saveReport
//		System.out.println("######################### Sauvegarde du rapport ######################### ");
//		saveReport("templates/test.xml", listener);
//
//		// stop ZAProxy
//		System.out.println("######################### Arrêt du daemon ZAP ######################### ");
//
//	}

//	public void startZAP(String url, String maxchildren, String scanPolicyName, BuildListener listener) {
//
//		System.out.println("######################### phase de spidering ######################### ");
//		String scanid = spiderURL(url, maxchildren, listener);
//
//		System.out.println("######################### Résultats de spidering ######################### ");
//		viewSpiderResults(scanid, listener);
//		System.out.println("########################################################################## ");
//
//		// scan
//		System.out.println("######################### phase de scan ######################### ");
//		scanURL(url, scanid, scanPolicyName, listener);
//
//		// saveReport
//		System.out.println("######################### Sauvegarde du rapport ######################### ");
//		saveReport("test.xml", listener);
//
//		// stop ZAProxy
//		System.out.println("######################### Arrêt du daemon ZAP ######################### ");
//
//	}

	/**
	 * Shuts down ZAP
	 */
	public void stopZap(String apikey, BuildListener listener) {

		try {
			ApiResponse status = api.shutdown(zapProxyKey);
			listener.getLogger().println(((ApiResponseElement) status).getValue());

		} catch (ClientApiException e) {
			
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
		}

	}

}
