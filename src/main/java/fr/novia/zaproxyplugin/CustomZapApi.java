package fr.novia.zaproxyplugin;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseFactory;
import org.zaproxy.clientapi.core.ClientApiException;

import hudson.model.BuildListener;

 



public class CustomZapApi implements Serializable {

	
	/**
	 * 
	 */
	private static final long serialVersionUID = -3728827419473825213L;
	private final String PROTOCOL="http";
	private  final  String zapProxyHost;
	private  final String zapProxyPort;
	private  final boolean  debug;


	private  BuildListener listener;
	
	public CustomZapApi(String zapProxyHost, String zapProxyPort, BuildListener listener, boolean  debug) {
		super();
		this.zapProxyHost = zapProxyHost;
		this.zapProxyPort = zapProxyPort;
		this.listener= listener;
		this.debug=debug;
	}
	
	public CustomZapApi(String PROTOCOL,String zapProxyHost, String zapProxyPort, BuildListener listener, boolean  debug) {
		super();
		//this.PROTOCOL=PROTOCOL;
		this.zapProxyHost = zapProxyHost;
		this.zapProxyPort = zapProxyPort;
		this.listener= listener;
		this.debug=debug;
	}
	 
	
	public CustomZapApi(String zapProxyHost, String zapProxyPort, boolean  debug) {
		// TODO Auto-generated constructor stub
		super();
		this.zapProxyHost = zapProxyHost;
		this.zapProxyPort = zapProxyPort;
		this.debug=debug;
		
	}


	/**
	 * @return the zapProxyHost
	 */
	public String getZapProxyHost() {
		return zapProxyHost;
	}




	/**
	 * @return the zapProxyPort
	 */
	public String getZapProxyPort() {
		return zapProxyPort;
	}


	
	/**
	 * @return the listener
	 */
	public BuildListener getListener() {
		return listener;
	}

	/**
	 * @param listener the listener to set
	 */
	public void setListener(BuildListener listener) {
		this.listener = listener;
	}
	
	
/**************************************** || VIEWS || ******************************************/
	
	
	
/****************** LIST SCRIPTS *************************/
	
	
	/**
	 * Lists the scripts available, with its engine, name, description, type and error state.
	 */
	public ApiResponse listScripts() throws ClientApiException {
		Map<String, String> map = null;
		return callApi("script", "view", "listScripts", map);
	}

/***************** HOME DIRECTORY *************************/
	
	public ApiResponse getZAPHomeDirectory() throws ClientApiException {
		Map<String, String> map = null;
		return callApi("core", "view", "homeDirectory", map);
	}
	
	
/************************* Authentification ****************/
	
	public ApiResponse getSupportedAuthenticationMethods() throws ClientApiException {
		Map<String, String> map = null;
		return callApi("authentication", "view", "getSupportedAuthenticationMethods", map);
	}
	
	public ApiResponse getAuthenticationMethodConfigParams(String authmethodname) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("authMethodName", authmethodname);
		return callApi("authentication", "view", "getAuthenticationMethodConfigParams", map);
	}
	
	public ApiResponse getAuthenticationCredentialsConfigParams(String contextid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("contextId", contextid);
		return callApi("users", "view", "getAuthenticationCredentialsConfigParams", map);
	}
	
	public ApiResponse getLoggedInIndicator(String contextid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("contextId", contextid);
		return callApi("authentication", "view", "getLoggedInIndicator", map);
	}
	
	public ApiResponse getLoggedOutIndicator(String contextid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("contextId", contextid);
		return callApi("authentication", "view", "getLoggedOutIndicator", map);
	}
	
	public ApiResponse getAuthenticationMethod(String contextid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("contextId", contextid);
		return callApi("authentication", "view", "getAuthenticationMethod", map);
	}
	
	
	public ApiResponse usersList(String contextid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("contextId", contextid);
		return callApi("users", "view", "usersList", map);
	}
	
	
	public ApiResponse getUserById(String contextid, String userid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("contextId", contextid);
		map.put("userId", userid);
		return callApi("users", "view", "getUserById", map);
	}
	
	
	
	public ApiResponse isForcedUserModeEnabled() throws ClientApiException {
		Map<String, String> map = null;
		return callApi("forcedUser", "view", "isForcedUserModeEnabled", map);
	}

	public ApiResponse getForcedUser(String contextid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("contextId", contextid);
		return callApi("forcedUser", "view", "getForcedUser", map);
	}
	
	public ApiResponse scanPolicyNames() throws ClientApiException {
		Map<String, String> map = null;
		return callApi("ascan", "view", "scanPolicyNames", map);
	}
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/**************************************** || ACTIONS || ******************************************/	
	
	public ApiResponse setLoggedInIndicator(String apikey, String contextid, String loggedinindicatorregex) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextId", contextid);
		map.put("loggedInIndicatorRegex", loggedinindicatorregex);
		return callApi("authentication", "action", "setLoggedInIndicator", map);
	}
	
	public ApiResponse setLoggedOutIndicator(String apikey, String contextid, String loggedoutindicatorregex) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextId", contextid);
		map.put("loggedOutIndicatorRegex", loggedoutindicatorregex);
		return callApi("authentication", "action", "setLoggedOutIndicator", map);
	}

	public ApiResponse setAuthenticationMethod(String apikey, String contextid, String authmethodname, String authmethodconfigparams) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextId", contextid);
		map.put("authMethodName", authmethodname);
		map.put("authMethodConfigParams", authmethodconfigparams);
		return callApi("authentication", "action", "setAuthenticationMethod", map);
	}
		
	public ApiResponse newUser(String apikey, String contextid, String name) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextId", contextid);
		map.put("name", name);
		return callApi("users", "action", "newUser", map);
	}	
	
	public ApiResponse setAuthenticationCredentials(String apikey, String contextid, String userid, String authcredentialsconfigparams) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextId", contextid);
		map.put("userId", userid);
		map.put("authCredentialsConfigParams", authcredentialsconfigparams);
		return callApi("users", "action", "setAuthenticationCredentials", map);
	}

	
	/******************************************* AjaxSpider.java ***********************************************************/
	
	/**
	 * This component is optional and therefore the API will only work if it is installed
	 */
	public ApiResponse ajaxScan(String apikey, String url, String inscope) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("url", url);
		map.put("inScope", inscope);
		return callApi("ajaxSpider", "action", "scan", map);
	}

	/**
	 * This component is optional and therefore the API will only work if it is installed
	 */
	public ApiResponse ajaxStatus() throws ClientApiException {
		Map<String, String> map = null;
		return callApi("ajaxSpider", "view", "status", map);
	}

	
	/**
	 * This component is optional and therefore the API will only work if it is installed
	 */
	public ApiResponse spiderStatus(Map<String, String> map) throws ClientApiException {
		 		
		
		return callApi("spider", "view", "status", map);
	}
	
	/**
	 * This component is optional and therefore the API will only work if it is installed
	 */
	public ApiResponse scanStatus(Map<String, String> map) throws ClientApiException {
		 		
		
		return callApi("ascan", "view", "status", map);
	}

	/**
	 * This component is optional and therefore the API will only work if it is installed
	 */
	public ApiResponse ajaxResults(String start, String count) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("start", start);
		map.put("count", count);
		return callApi("ajaxSpider", "view", "results", map);
	}
	
	/**
	 * This component is optional and therefore the API will only work if it is installed
	 */
	public ApiResponse ajaxResults( ) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		 
		return callApi("ajaxSpider", "view", "results", map);
	}

	/**
	 * This component is optional and therefore the API will only work if it is installed
	 */
	public ApiResponse ajaxNumberOfResults() throws ClientApiException {
		Map<String, String> map = null;
		return callApi("ajaxSpider", "view", "numberOfResults", map);
	}
	
	/**
	 * This component is optional and therefore the API will only work if it is installed
	 */
	public ApiResponse ajaxSpiderStop(String apikey) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		return callApi("ajaxSpider", "action", "stop", map);
	}
	
	/********************************************** ForcedUser.java *************************************************************/


	public ApiResponse setForcedUser(String apikey, String contextid, String userid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextId", contextid);
		map.put("userId", userid);
		return callApi("forcedUser", "action", "setForcedUser", map);
	}

	public ApiResponse setForcedUserModeEnabled(String apikey, boolean bool) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("boolean", Boolean.toString(bool));
		return callApi("forcedUser", "action", "setForcedUserModeEnabled", map);
	}
	
	
	/****************************************************************************************************************************/
	public ApiResponse scanAsUser(String apikey, String url, String contextid, String userid, String recurse, String ScanPolicyName) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("url", url);
		map.put("contextId", contextid);
		map.put("userId", userid);
		map.put("recurse", recurse);
		map.put("ScanPolicyName", ScanPolicyName);
		return callApi("ascan", "action", "scanAsUser", map);
	}
	
	public ApiResponse scan(Map<String, String> params) throws ClientApiException {
          return  callApi("ascan", "action", "scan",params);
	 
	}
	
	public ApiResponse spiderAsUser(String apikey, String url, String contextid, String userid, String maxchildren) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("url", url);
		map.put("contextId", contextid);
		map.put("userId", userid);
		map.put("maxChildren", maxchildren);
		return callApi("spider", "action", "scanAsUser", map);
	}
	
	public ApiResponse spider(String apikey, String url,  String maxchildren) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("url", url);
		map.put("maxChildren", maxchildren);
		return callApi("spider", "action", "scan", map);
	}

	
	
	/********************** SESSION ************************/

	/**
	 * Loads the session with the given name. If a relative path is specified it will be resolved against the "session" directory in ZAP "home" dir.
	 */
	public ApiResponse loadSession(String apikey, String name) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("name", name);
		return callApi("core", "action", "loadSession", map);
	}
	
	/**
	 * Save the session with the given name. If a relative path is specified it will be resolved against the "session" directory in ZAP "home" dir.
	 */
	
	public ApiResponse saveSession(String apikey, String name, String overwrite) throws ClientApiException {
        Map<String, String> map = null;
        map = new HashMap<String, String>();
        if (apikey != null) {
                map.put("apikey", apikey);
        }
        map.put("name", name);
        map.put("overwrite", overwrite);
        return callApi("core", "action", "saveSession", map);
}
	
	
	/**
	 * Creates a new session, optionally overwriting existing files. If a relative path is specified it will be resolved against the "session" directory in ZAP "home" dir.
	 */
	public ApiResponse newSession(String apikey, String name, String overwrite) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("name", name);
		map.put("overwrite", overwrite);
		return callApi("core", "action", "newSession", map);
	}

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	/**
	 * Creates a new context in the current session
	 */
	public ApiResponse newContext(String apikey, String contextname) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextName", contextname);
		return callApi("context", "action", "newContext", map);
	}
	
	/**
	 * List context names of current session
	 */
	public ApiResponse contextList() throws ClientApiException {
		Map<String, String> map = null;
		return callApi("context", "view", "contextList", map);
	}

	/**
	 * List the information about the named context
	 */
	public ApiResponse context(String contextname) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("contextName", contextname);
		return callApi("context", "view", "context", map);
	}

	/**
	 * Add include regex to context
	 */
	public ApiResponse includeInContext(String apikey, String contextname, String regex) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextName", contextname);
		map.put("regex", regex);
		return callApi("context", "action", "includeInContext", map);
	}
	
	/**
	 * Add exclude regex to context
	 */
	public ApiResponse excludeFromContext(String apikey, String contextname, String regex) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextName", contextname);
		map.put("regex", regex);
		return callApi("context", "action", "excludeFromContext", map);
	}

	
	public ApiResponse setUserEnabled(String apikey, String contextid, String userid, String enabled) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("contextId", contextid);
		map.put("userId", userid);
		map.put("enabled", enabled);
		return callApi("users", "action", "setUserEnabled", map);
	}
	
	public ApiResponse results(String scanid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("scanId", scanid);
		return callApi("spider", "view", "results", map);
	}
	
	public ApiResponse fullResults(String scanid) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("scanId", scanid);
		return callApi("spider", "view", "fullResults", map);
	}
	/***************************************************************************/
   
	public  int statusToInt(final ApiResponse response) {
		return Integer.parseInt(((ApiResponseElement) response).getValue());
	}

	public URL buildZapRequestUrl( String format, String component,
			String type, String method, Map<String, String> params) throws MalformedURLException {
		StringBuilder sb = new StringBuilder();
		sb.append(PROTOCOL+"://" + this.getZapProxyHost() + ":" + this.getZapProxyPort() + "/");
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
				sb.append(encodeQueryParam(p.getKey()));
				sb.append('=');
				if (p.getValue() != null) {
					sb.append(encodeQueryParam(p.getValue()));
				}
				sb.append('&');
			}
		}
		//debug=true
        //System.out.println(sb.toString());
		
		if(debug == true )
		this.listener.getLogger().println(sb.toString());
		
		return new URL(sb.toString());
	}

	public static String encodeQueryParam(String param) {
		try {
			return URLEncoder.encode(param, "UTF-8");
		} catch (UnsupportedEncodingException ignore) {
			// UTF-8 is a standard charset.
		}
		return param;
	}
/********************************************************************************************************************/
	public ApiResponse enableAllScanners(String apikey, String scanpolicyname) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("scanPolicyName", scanpolicyname);
		return callApi("ascan", "action", "enableAllScanners", map);
	}
	
	public ApiResponse disableAllScanners(String apikey, String scanpolicyname) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("scanPolicyName", scanpolicyname);
		return callApi("ascan", "action", "disableAllScanners", map);
	}
	
	public ApiResponse enableScanners(String apikey, String ids) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("ids", ids);
		return callApi("ascan", "action", "enableScanners", map);
	}

	public ApiResponse disableScanners(String apikey, String ids) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("ids", ids);
		return callApi("ascan", "action", "disableScanners", map);
	}
	
	public ApiResponse setEnabledPolicies(String apikey, String ids) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("ids", ids);
		return callApi("ascan", "action", "setEnabledPolicies", map);
	}

	/********************************************************************************************************************/	
	//10014 : CSRF
	//http://10.107.2.102:8080/xml/ascan/action/setPolicyAttackStrength/?id=10014&attackStrength=HIGH&scanPolicyName=Default%20policy&apikey=2q0ap4er4dhnlauq165mv43cht
	public ApiResponse setPolicyAttackStrength(String apikey, String id, String attackstrength, String scanpolicyname) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("id", id);
		map.put("attackStrength", attackstrength);
		map.put("scanPolicyName", scanpolicyname);
		return callApi("ascan", "action", "setPolicyAttackStrength", map);
	}

	public ApiResponse setPolicyAlertThreshold(String apikey, String id, String attackstrength, String scanpolicyname) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("id", id);
		map.put("alertThreshold", attackstrength);
		map.put("scanPolicyName", scanpolicyname);
		return callApi("ascan", "action", "setPolicyAlertThreshold", map);
	}

	public ApiResponse setScannerAttackStrength(String apikey, String id, String attackstrength, String scanpolicyname) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("id", id);
		map.put("attackStrength", attackstrength);
		map.put("scanPolicyName", scanpolicyname);
		return callApi("ascan", "action", "setScannerAttackStrength", map);
	}

	public ApiResponse setScannerAlertThreshold(String apikey, String id, String alertThreshold, String scanpolicyname) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("id", id);
		map.put("alertThreshold", alertThreshold);
		map.put("scanPolicyName", scanpolicyname);
		return callApi("ascan", "action", "setScannerAlertThreshold", map);
	}
	
	
	/************************************************************************************************************************/

	public Document callApiDom (String component, String type, String method,
			Map<String, String> params) throws ClientApiException {
		try {
			URL url = buildZapRequestUrl("xml", component, type, method, params);
			//System.out.println(url.toString());
			HttpURLConnection uc = (HttpURLConnection)url.openConnection();
			//get the factory
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			//Using factory get an instance of document builder
			DocumentBuilder db = dbf.newDocumentBuilder();
			//parse using builder to get DOM representation of the XML file
			return db.parse(uc.getInputStream());
		} catch (Exception e) {
			throw new ClientApiException(e);
		}
	}

	public ApiResponse callApi (String component, String type, String method,Map<String, String> params) throws ClientApiException {
		Document dom;
		try {
			dom = callApiDom(component, type, method, params);
			//System.out.println(dom.getTextContent());
		} catch (Exception e) {
			throw new ClientApiException(e);
		}
		return ApiResponseFactory.getResponse(dom.getFirstChild());
	}
	
	
	public ApiResponse numberOfAlerts(String baseurl) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("baseurl", baseurl);
		return callApi("core", "view", "numberOfAlerts", map);
	}
	
	public ApiResponse numberOfMessages(String baseurl) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		map.put("baseurl", baseurl);
		return callApi("core", "view", "numberOfMessages", map);
	}
	
	/**
	 * Generates a report in XML format
	 */
	public byte[] xmlreport(String apikey) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		return callApiOther("core", "other", "xmlreport", map);
	}
	
	/**
	 * Generates a report in HTML format
	 */
	public byte[] htmlreport(String apikey) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		return callApiOther("core", "other", "htmlreport", map);
	}
	
	public   byte[] callApiOther (String component, String type, String method,
			Map<String, String> params) throws ClientApiException {
		try {
			URL url = buildZapRequestUrl("other", component, type, method, params);
			//System.out.println(url);
			HttpURLConnection uc = (HttpURLConnection)url.openConnection();
			InputStream in = uc.getInputStream();
			ByteArrayOutputStream out = new ByteArrayOutputStream();
			byte[] buffer = new byte[8 * 1024];
			try {
				int bytesRead;
			    while ((bytesRead = in.read(buffer)) != -1) {
			    	out.write(buffer, 0, bytesRead);
			    }
			} catch (IOException e) {
				throw new ClientApiException(e);
			} finally {
				out.close();
				in.close();
			}
			return out.toByteArray();
			
		} catch (Exception e) {
			throw new ClientApiException(e);
		}
	}
	/**
	 * Shuts down ZAP
	 */
	public ApiResponse shutdown(String apikey) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		return callApi("core", "action", "shutdown", map);
	}
	
	
/*********************************************************************************************************************/	
	
	public ApiResponse PsEnableAllScanners(String apikey) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		return callApi("pscan", "action", "enableAllScanners", map);
	}

	public ApiResponse PsDisableAllScanners(String apikey) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		return callApi("pscan", "action", "disableAllScanners", map);
	}
	public ApiResponse setOptionPostForm(String apikey, boolean bool) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("Boolean", Boolean.toString(bool));
		return callApi("spider", "action", "setOptionPostForm", map);
	}

	public ApiResponse setOptionProcessForm(String apikey, boolean bool) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("Boolean", Boolean.toString(bool));
		return callApi("spider", "action", "setOptionProcessForm", map);
	}
	
	public ApiResponse setOptionParseComments(String apikey, boolean bool) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("Boolean", Boolean.toString(bool));
		return callApi("spider", "action", "setOptionParseComments", map);
	}

	public ApiResponse setOptionParseRobotsTxt(String apikey, boolean bool) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("Boolean", Boolean.toString(bool));
		return callApi("spider", "action", "setOptionParseRobotsTxt", map);
	}

	public ApiResponse setOptionParseSitemapXml(String apikey, boolean bool) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("Boolean", Boolean.toString(bool));
		return callApi("spider", "action", "setOptionParseSitemapXml", map);
	}
	
	public ApiResponse setOptionHandleODataParametersVisited(String apikey, boolean bool) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("Boolean", Boolean.toString(bool));
		return callApi("spider", "action", "setOptionHandleODataParametersVisited", map);
	}
	
	public ApiResponse setOptionMaxDepth(String apikey, int i) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("Integer", Integer.toString(i));
		return callApi("spider", "action", "setOptionMaxDepth", map);
	}
	
	public ApiResponse setOptionShowAdvancedDialog(String apikey, boolean bool) throws ClientApiException {
		Map<String, String> map = null;
		map = new HashMap<String, String>();
		if (apikey != null) {
			map.put("apikey", apikey);
		}
		map.put("Boolean", Boolean.toString(bool));
		return callApi("spider", "action", "setOptionShowAdvancedDialog", map);
	}


}
