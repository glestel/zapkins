
package fr.novia.zaproxyplugin;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.Authenticator;
import java.net.URLEncoder;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;

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

public class CustomZapClientApi {


	 
	 
	private String zapProxyHost = ""; 
	private  int zapProxyPort = 8080; 
	private  String zapProxyKey =""; 
	private CustomZapApi api;
	
	private BuildListener listener;
 
	
	 
	public CustomZapClientApi(String ZAP_ADDRESS,int zapProxyPort, String ZAP_API_KEY , BuildListener listener) {
		super();
		
		
		this.zapProxyHost = ZAP_ADDRESS ;
		this.zapProxyPort = zapProxyPort;
		this.zapProxyKey =ZAP_API_KEY;
		this.listener=listener;
		this.api = new CustomZapApi(ZAP_ADDRESS,""+zapProxyPort+"", listener);
	}
	
	
//	private String webProxyProperties=new File(".").getAbsolutePath()+"/webproxy.properties";
//	private String authenticationProperties=new File(".").getAbsolutePath()+"/authentication.properties";
//	private static String zapProperties=new File(".").getAbsolutePath()+"/zap.properties";

//	private static final String ZAP_ADDRESS = PropertyLoader.getValueFromKey("ZAPHOST", "10.107.2.102", zapProperties);
//	private static final int ZAP_PORT = Integer.parseInt(PropertyLoader.getValueFromKey("ZAPPORT", "8080", zapProperties));
//	private static final String ZAP_API_KEY =PropertyLoader.getValueFromKey("ZAPAPIKEY","2q0ap4er4dhnlauq165mv43cht", zapProperties);//"2ec2s1qh8fu1303jar3us1msb4";//"2q0ap4er4dhnlauq165mv43cht";

	/***************************************************************************************************************************/

	
	
	
	
	
	
	/***************************** USER CONFIG *************************************************************/
	
	public void listUserConfigInformation(String contextId, BuildListener listener)  {
		// Check out which are the config parameters required to set up an user with the currently
		// set authentication methods
		//String contextId = PropertyLoader.getValueFromKey("CONTEXTID", "1", authenticationProperties);
		
		/************************************************************************************************************/
		ApiResponseList configParamsList = null;
		try {
			configParamsList = (ApiResponseList) api.getAuthenticationCredentialsConfigParams(contextId);
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		/************************************************************************************************************/
		
		
		StringBuilder sb = new StringBuilder("Users' config params: ");
		for (ApiResponse r : configParamsList.getItems()) {
			ApiResponseSet set = (ApiResponseSet) r;
			sb.append(set.getAttribute("name")).append(" (");
			sb.append((set.getAttribute("mandatory").equals("true") ? "mandatory" : "optional"));
			sb.append("), ");
		}
		//System.out.println(sb.deleteCharAt(sb.length() - 2).toString());
		listener.getLogger().println(sb.deleteCharAt(sb.length() - 2).toString());
	}
	
	private static String extractUserId(ApiResponse response) {
		return ((ApiResponseElement) response).getValue();
	}
	
	
	
	
	
	
	
	
	
	/**************************** CONTEXT CONFIG ***********************************************************/
	
	public String getContextId( String contextname, BuildListener listener){
		
		
		try {
 
			ApiResponseSet set = (ApiResponseSet) api.context(contextname);
			return set.getAttribute("id");		
			
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			//System.out.println("Context dose not exist\nIt will be created...");
			listener.getLogger().println("Context dose not exist\nIt will be created...");
			try {
				api.newContext(zapProxyKey, contextname);
				//System.out.println("Context created...");
				listener.getLogger().println("Context created...");
				return getContextId(contextname, listener);
			} catch (ClientApiException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}
			//e.printStackTrace();
		}
		return null;
	}
	
	
	
    /**************************** AUTHENTICATION CONFIG******************************************************/	
	
	/**
	 * permet de spécifier le pattern permettant à ZAP de s'assurer que l'utilisateur est bien authentifié
	 * @param api
	 * @param contextId
	 * @throws UnsupportedEncodingException
	 * @throws ClientApiException
	 */
	
	public void setLoggedInIndicator( String contextId, String loggedInIndicator, BuildListener listener)  {
		// Prepare values to set, with the logged in indicator as a regex matching the logout link
//		String loggedInIndicator =PropertyLoader.getValueFromKey("LOGGEDININDICATOR", "", authenticationProperties);  
		
		//String contextId = PropertyLoader.getValueFromKey("CONTEXTID", "", authenticationProperties);//"1";

		// Actually set the logged in indicator
		/************************************************************************************************************/
		//api.setLoggedInIndicator(ZAP_API_KEY, contextId, java.util.regex.Pattern.quote(loggedInIndicator));
		try {
			api.setLoggedInIndicator(zapProxyKey, contextId, loggedInIndicator);
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		/************************************************************************************************************/

		// Check out the logged in indicator that is set
		/************************************************************************************************************/
		try {
			//System.out.println("Configured logged in indicator regex: "	+ ((ApiResponseElement) api.getLoggedInIndicator(contextId)).getValue());
			listener.getLogger().println("Configured logged in indicator regex: "	+ ((ApiResponseElement) api.getLoggedInIndicator(contextId)).getValue());
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		/************************************************************************************************************/
	}
	
	/**
	 * permet de définir le pattern permettant à ZAP de savoir que l'utilisateur n'est pas (plus) authentiifé
	 * @param api
	 * @param contextId
	 * @throws UnsupportedEncodingException
	 * @throws ClientApiException
	 */
	public void setLoggedOutIndicator(String contextId, String loggedOutIndicator, BuildListener listener)  {
		// Prepare values to set, with the logged in indicator as a regex matching the logout link
//		String loggedOutIndicator =PropertyLoader.getValueFromKey("LOGGEDOUTINDICATOR", "", authenticationProperties); //"<a href=\"logout.jsp\">Logout</a>";
		
		//String contextId = PropertyLoader.getValueFromKey("CONTEXTID", "", authenticationProperties);//"1";

		// Actually set the logged in indicator
		/************************************************************************************************************/
		//api.setLoggedOutIndicator(ZAP_API_KEY, contextId, java.util.regex.Pattern.quote(loggedOutIndicator));
		try {
			api.setLoggedOutIndicator(zapProxyKey, contextId,  loggedOutIndicator);
			/************************************************************************************************************/

			// Check out the logged in indicator that is set
			/************************************************************************************************************/
			//System.out.println("Configured logged Out indicator regex: "	+ ((ApiResponseElement) api.getLoggedOutIndicator(contextId)).getValue());
			listener.getLogger().println("Configured logged Out indicator regex: "	+ ((ApiResponseElement) api.getLoggedOutIndicator(contextId)).getValue());
			/************************************************************************************************************/
			
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	/**
	 * permet de définir les paramètres d'authentification
	 * @param api
	 * @param contextId
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException
	 */
	private  void setFormBasedAuthentication(String contextId, String loginUrl, String loginRequestData, BuildListener listener)  {
		// Setup the authentication method
 
//		String loginUrl = PropertyLoader.getValueFromKey("LOGINURL", "", authenticationProperties); 
//		String loginRequestData = PropertyLoader.getValueFromKey("LOGINREQUESTDATA", "", authenticationProperties); 

		// Prepare the configuration in a format similar to how URL parameters are formed. This
		// means that any value we add for the configuration values has to be URL encoded.
		StringBuilder formBasedConfig = new StringBuilder();
		try {
			formBasedConfig.append("loginUrl=").append(URLEncoder.encode(loginUrl, "UTF-8"));
			formBasedConfig.append("&loginRequestData=").append(URLEncoder.encode(loginRequestData, "UTF-8"));

			//System.out.println("Setting form based authentication configuration as: "+ formBasedConfig.toString());
			listener.getLogger().println("Setting form based authentication configuration as: "+ formBasedConfig.toString());
			
			/************************************************************************************************************/
			api.setAuthenticationMethod(zapProxyKey, contextId, "formBasedAuthentication",formBasedConfig.toString());
			/************************************************************************************************************/
			

			// Check if everything is set up ok
			/************************************************************************************************************/
			//System.out.println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));
			listener.getLogger().println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));
			/************************************************************************************************************/
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void setScriptBasedAuthentication(String contextId, String LoginUrl,String postData, String Cookie, String scriptName, BuildListener listener  ) {

// Setup the authentication method
//String LoginUrl = PropertyLoader.getValueFromKey("LOGINURL", "", authenticationProperties); 
//String postData = PropertyLoader.getValueFromKey("POSTDATAWITHOUTCREDENTIALS", "", authenticationProperties);
//String Cookie=PropertyLoader.getValueFromKey("COOKIE", "", authenticationProperties);
//String scriptName=PropertyLoader.getValueFromKey("SCRIPTNAME", "", authenticationProperties);


// Prepare the configuration in a format similar to how URL parameters are formed. This
// means that any value we add for the configuration values has to be URL encoded.
StringBuilder scriptBasedConfig = new StringBuilder();
try {
	scriptBasedConfig.append("scriptName=").append(URLEncoder.encode(scriptName, "UTF-8"));
	scriptBasedConfig.append("&LoginUrl=").append(URLEncoder.encode(LoginUrl, "UTF-8"));
	scriptBasedConfig.append("&postData=").append(URLEncoder.encode(postData, "UTF-8"));
	scriptBasedConfig.append("&Cookie=").append(URLEncoder.encode(Cookie, "UTF-8"));
	//System.out.println("Setting Script based authentication configuration as: "+ scriptBasedConfig .toString());
	listener.getLogger().println("Setting Script based authentication configuration as: "+ scriptBasedConfig .toString());
	/************************************************************************************************************/
	//http://10.107.2.102:8080/JSON/authentication/action/setAuthenticationMethod/?zapapiformat=JSON&apikey=2q0ap4er4dhnlauq165mv43cht&contextId=1&authMethodName=scriptBasedAuthentication&authMethodConfigParams=scriptName%3Db.espaceclientv3.orange.fr.js
	api.setAuthenticationMethod(zapProxyKey, contextId, "scriptBasedAuthentication",scriptBasedConfig .toString());
	/************************************************************************************************************/


	// Check if everything is set up ok
	/************************************************************************************************************/
	//System.out.println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));
	listener.getLogger().println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));
	/************************************************************************************************************/
	 
} catch (UnsupportedEncodingException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
} catch (ClientApiException e) {
	// TODO Auto-generated catch block
	e.printStackTrace();
}



}
	/**
	 * permet de définir les paramètres d'authentification
	 * @param api
	 * @param contextId
	 * @param loginUrl
	 * @param loginRequestData
	 * @throws ClientApiException
	 * @throws UnsupportedEncodingException
	 */
	
//private  void setFormBasedAuthentication( String contextId, String loginUrl, String loginRequestData)  {
//// Setup the authentication method
//// Prepare the configuration in a format similar to how URL parameters are formed. This
//// means that any value we add for the configuration values has to be URL encoded.
//StringBuilder formBasedConfig = new StringBuilder();
//formBasedConfig.append("loginUrl=").append(URLEncoder.encode(loginUrl, "UTF-8"));
//formBasedConfig.append("&loginRequestData=").append(URLEncoder.encode(loginRequestData, "UTF-8"));
//
//System.out.println("Setting form based authentication configuration as: "+ formBasedConfig.toString());
//
///************************************************************************************************************/
//api.setAuthenticationMethod(ZAP_API_KEY, contextId, "formBasedAuthentication",formBasedConfig.toString());
///************************************************************************************************************/
//
//
//// Check if everything is set up ok
///************************************************************************************************************/
//System.out.println("Authentication config: " + api.getAuthenticationMethod(contextId).toString(0));
///************************************************************************************************************/
//}
//


///**
// * permet de définir les données d'authentification liées à l'utilisateur
// * @param api
// * @param contextId
// * @return
// * @throws ClientApiException
// * @throws UnsupportedEncodingException
// */
// 
//private  String  setUserAuthConfig(String contextId, String user, String username, String password)   {
//		// Prepare info
////		//String contextId = PropertyLoader.getValueFromKey("CONTEXTID", "", authenticationProperties);//"1";
////		String user = PropertyLoader.getValueFromKey("USER", "User Test", authenticationProperties);//"Test User";
////		String username = PropertyLoader.getValueFromKey("USERNAME", "ZAP", authenticationProperties);//"test@example.com";
////		String password = PropertyLoader.getValueFromKey("PASSWORD", "ZAP", authenticationProperties);//"weakPassword";
//
//		/************************************************************************************************************/
//		// Make sure we have at least one user
//		String userId = null;
//		try {
//			userId = extractUserId(api.newUser(ZAP_API_KEY, contextId, user));
//			/************************************************************************************************************/
//
//			// Prepare the configuration in a format similar to how URL parameters are formed. This
//			// means that any value we add for the configuration values has to be URL encoded.
//			StringBuilder userAuthConfig = new StringBuilder();
//			userAuthConfig.append("Username=").append(URLEncoder.encode(username, "UTF-8"));
//			userAuthConfig.append("&Password=").append(URLEncoder.encode(password, "UTF-8"));
//
//			System.out.println("Setting user authentication configuration as: " + userAuthConfig.toString());
//			
//			/************************************************************************************************************/
//			api.setAuthenticationCredentials(ZAP_API_KEY, contextId, userId, userAuthConfig.toString());
//			/************************************************************************************************************/
//
//			// Check if everything is set up ok
//			System.out.println("Authentication config: " + api.getUserById(contextId, userId).toString(0));
//			
//			
//			
//			
//		} catch (ClientApiException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		} catch (UnsupportedEncodingException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//
//		return userId;
//	}

/**
 * permet de spécifier les données d'authentification liées à l'utilisateur
 * @param api
 * @param contextId
 * @param user nom de l'utilisateur utilisé dans le test
 * @param username
 * @param password
 * @return
 * @throws ClientApiException
 * @throws UnsupportedEncodingException
 */

public String  setUserAuthConfig(String contextId, String user, String username, String password, BuildListener listener) {
	 

	/************************************************************************************************************/
	// Make sure we have at least one user
	String userId = null;
	try {
		userId = extractUserId(api.newUser(zapProxyKey, contextId, user));
		/************************************************************************************************************/

		// Prepare the configuration in a format similar to how URL parameters are formed. This
		// means that any value we add for the configuration values has to be URL encoded.
		StringBuilder userAuthConfig = new StringBuilder();
		userAuthConfig.append("Username=").append(URLEncoder.encode(username, "UTF-8"));
		userAuthConfig.append("&Password=").append(URLEncoder.encode(password, "UTF-8"));

		//System.out.println("Setting user authentication configuration as: " + userAuthConfig.toString());
		listener.getLogger().println("Setting user authentication configuration as: " + userAuthConfig.toString());
		
		/************************************************************************************************************/
		api.setAuthenticationCredentials(zapProxyKey, contextId, userId, userAuthConfig.toString());
		/************************************************************************************************************/

		// Check if everything is set up ok
		//System.out.println("Authentication config: " + api.getUserById(contextId, userId).toString(0));
		listener.getLogger().println("Authentication config: " + api.getUserById(contextId, userId).toString(0));
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (UnsupportedEncodingException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	
	return userId;
}

/**
 * permet d'inclure une url dans un contexte
 * @param api
 * @param url
 */
public void includeInContext(String url, String contextname, BuildListener listener ){
		//String contextname=PropertyLoader.getValueFromKey("CONTEXTNAME", "", authenticationProperties);
		try {
			 
			ApiResponse status=api.includeInContext(zapProxyKey, contextname, url);
			//System.out.println(((ApiResponseElement) status).getValue());
			listener.getLogger().println(((ApiResponseElement) status).getValue());
			
			
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
///**
// * permet d'inclure une url dans un contexte
// * @param api
// * @param url
// * @param contextname
// */
//public void includeInContext(CustomZapApi api, String url, String contextname){
//	 
//	try {
//		 
//		ApiResponse status=api.includeInContext(ZAP_API_KEY, contextname,url);
//		System.out.println(((ApiResponseElement) status).getValue());
//		
//		
//		
//	} catch (ClientApiException e) {
//		// TODO Auto-generated catch block
//		e.printStackTrace();
//	}
//	
//}
/**
* permet d'inclure une url dans un contexte
* @param api
* @param url
*/
public void excludeFromContext(String url, String contextname, BuildListener listener){
		//String contextname=PropertyLoader.getValueFromKey("CONTEXTNAME", "", authenticationProperties);
		try {
			 
			ApiResponse status=api.excludeFromContext(zapProxyKey, contextname, url);
			//System.out.println(((ApiResponseElement) status).getValue());
			listener.getLogger().println(((ApiResponseElement) status).getValue());
			
			
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}



public void enableUser(String contextid, String userid, BuildListener listener){
	
	try {
		ApiResponse status=api.setUserEnabled(zapProxyKey, contextid, userid, "true");
		//System.out.println(((ApiResponseElement) status).getValue());
		listener.getLogger().println(((ApiResponseElement) status).getValue());
		
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
}

// a voir comment l'implementer
public  void setWebProxyDetails(String webProxyPropertiesPath) {

	System.setProperty("http.proxyHost", PropertyLoader.getValueFromKey("PROXYHOST", "", webProxyPropertiesPath));
	System.setProperty("http.proxyPort", PropertyLoader.getValueFromKey("PROXYPORT", "", webProxyPropertiesPath));
	Authenticator.setDefault(new ProxyAuthenticator(PropertyLoader.getValueFromKey("USER", "", webProxyPropertiesPath), PropertyLoader.getValueFromKey("PASSWORD", "", webProxyPropertiesPath)));
}

//a voir comment l'implementer
public  void setWebProxyDetails(String webProxyHost, int webProxyPort, String webProxyUser, String webProxyPassword) {

	System.setProperty("http.proxyHost", webProxyHost);
	System.setProperty("http.proxyPort", String.valueOf(webProxyPort));
	Authenticator.setDefault(new ProxyAuthenticator(webProxyUser, webProxyPassword));
}

/***************************** GENERAl CONFIG ********************************/

public ApiResponse setPolicyAttackStrength( String id, String attackstrength, String scanpolicyname)  {
	
	try {
		return api.setPolicyAttackStrength(zapProxyKey, id, attackstrength, scanpolicyname);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 
	return null;
}


public ApiResponse setPolicyAlertThreshold( String id, String attackstrength, String scanpolicyname){
	
	
	try {
		api.setPolicyAlertThreshold(zapProxyKey, id, attackstrength, scanpolicyname);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 
	return null;
}
/**************************** SESSION *******************************/
/**
 * Loads the session with the given name. If a relative path is specified it will be resolved against the "session" directory in ZAP "home" dir.
 */
public ApiResponse loadSession(String name)  {
	
	
	try {
		return api.loadSession(zapProxyKey, name);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 return null;
}


public void saveSession( String name, String overwrite, BuildListener listener )   {
	
	
	try {
		ApiResponse status = api.saveSession("+apikey+", name, overwrite);
		listener.getLogger().println(((ApiResponseElement) status).getValue());
		
		
		
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
 
}
/**************************************************************************/


public ApiResponse setOptionPostForm(boolean bool)   {
	
	try {
		return api.setOptionPostForm(zapProxyKey, bool);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return null;
}

public ApiResponse setOptionProcessForm(boolean bool)   {
	
	try {
		return api.setOptionProcessForm(zapProxyKey, bool);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 return null;
}

public ApiResponse setOptionHandleODataParametersVisited(  boolean bool)   {
	
	try {
		return api.setOptionHandleODataParametersVisited(zapProxyKey, bool);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 return null;
}

public ApiResponse setOptionShowAdvancedDialog(  boolean bool)   {
	
	try {
		return api.setOptionShowAdvancedDialog(zapProxyKey, bool);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 return null;
}

public ApiResponse setOptionParseComments(boolean bool)  {
	
	try {
		return api.setOptionParseComments(zapProxyKey, bool);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 return null;
}

public ApiResponse setOptionParseRobotsTxt(boolean bool)  {
	
	try {
		return api.setOptionParseRobotsTxt(zapProxyKey, bool);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 return null;
}

public ApiResponse setOptionParseSitemapXml(boolean bool){
	 try {
		return api.setOptionParseSitemapXml(zapProxyKey, bool);
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 return null;
}


/**
 * List context names of current session
 */
public String getContextList()  {
	
	ApiResponse response = null;
	try {
		response = api.contextList();
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	return ((ApiResponseElement)response).getValue();
	 
}



/*************************************************** Spidering ******************************************************************/

/**
 * phase de spidering en mode authentifié
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
public String spiderAsUserURL( String url, String contextid, String userid, String maxchildren, BuildListener listener ) {
 
			
			//ETAPE1 : envoyer la requête pour lancer le spidering :  
			//http://zap/xml/spider/action/scan/?apikey=XXX&maxChildren=&url=XXX
			ApiResponse status;
			String  scanid = null;
			try {
				status = api.spiderAsUser(zapProxyKey, url, contextid, userid, maxchildren);
				//ETAPE2 : chaque scan est identifié par un id 
				scanid = ((ApiResponseElement) status).getValue();
	 
				//ETAPE3 : Poll the status until it completes
				         
	            Map<String, String> params2 = new HashMap<String, String>();
	    		params2.put("scanid", scanid);
	    		int progress;

				while (true) {
					Thread.sleep(1000);
					//http://zap/xml/spider/view/status/?scanId=XXX 
					status =api.spiderStatus(params2);
					progress = Integer.parseInt(((ApiResponseElement) status).getValue());
					//progressBar.setValue(progress);
					//System.out.println("Spider progress : " + progress + "%");
					listener.getLogger().println("Spider progress : " + progress + "%");
					//textAreaLog.append("Spider progress : " + progress + "%\n");
					if (progress >= 100) {
						break;
					}
				}
				//System.out.println("Spider complete");
				listener.getLogger().println("Spider complete");
				//textAreaLog.append("phase de Spidering terminé\n");				
				
			} catch (ClientApiException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
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
public String spiderURL( String url, String maxchildren , BuildListener listener) {		
			
			//ETAPE1 : envoyer la requête pour lancer le spidering :  
			//http://zap/xml/spider/action/scan/?apikey=XXX&maxChildren=&url=XXX
			ApiResponse status;
			String  scanid=null;
			try {
				status = api.spider(zapProxyKey, url, maxchildren);
				//ETAPE2 : chaque scan est identifié par un id 
				scanid = ((ApiResponseElement) status).getValue();
	 
				//ETAPE3 : Poll the status until it completes
				         
	            Map<String, String> params2 = new HashMap<String, String>();
	    		params2.put("scanid", scanid);
	    		int progress;

				while (true) {
					Thread.sleep(1000);
					//http://zap/xml/spider/view/status/?scanId=XXX 
					status =api.spiderStatus(params2);
					progress = Integer.parseInt(((ApiResponseElement) status).getValue());
					//progressBar.setValue(progress);
					//System.out.println("Spider progress : " + progress + "%");
					listener.getLogger().println("Spider progress : " + progress + "%");
					//textAreaLog.append("Spider progress : " + progress + "%\n");
					if (progress >= 100) {
						break;
					}
				}
				//System.out.println("Spider complete");
				listener.getLogger().println("Spider complete");
				//textAreaLog.append("phase de Spidering terminé\n");
				
				
				
				
				
				
				
				
				
			} catch (ClientApiException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
			
			return scanid;
	}


public String ajaxSpiderURL(String url,String inscope, BuildListener listener ) {		
		 String result, METHOD, URL;
		 String [] splitedResult,header;
		//ETAPE1 : envoyer la requête pour lancer le spidering :  
		//http://zap/xml/spider/action/scan/?apikey=XXX&maxChildren=&url=XXX
		ApiResponse status;
		String  scanid=null;
		try {
			status = api.ajaxScan(zapProxyKey, url, inscope);
			
			//ETAPE2 : chaque scan est identifié par un id 
			scanid = ((ApiResponseElement) status).getValue();

			//ETAPE3 : Poll the status until it completes
	 
			String progress;

			while (true) {
				Thread.sleep(2500);
				//http://zap/xml/spider/view/status/?scanId=XXX 
				status =api.ajaxStatus();
				progress = ((ApiResponseElement) status).getValue();
				//progressBar.setValue(progress);
				//System.out.println("Ajax Spider progress : " + progress);
				listener.getLogger().println("Ajax Spider progress : " + progress);
				//textAreaLog.append("Spider progress : " + progress + "%\n");
				String nbrOfResults  = ((ApiResponseElement) api.ajaxNumberOfResults()).getValue();
				//System.out.println("Number of results : "+nbrOfResults);
				listener.getLogger().println("Number of results : "+nbrOfResults);
//				
//				try {
//					 ApiResponseList results = (ApiResponseList) (api.ajaxResults(nbrOfResults,"1"));
//					 
	//
//								for (ApiResponse r : results.getItems()) {
//									
//									
//									//cet appel affiche tous les attributs et leurs valeurs 
//									//System.out.println(((ApiResponseSet) r).toString(1));
//									//attributes : id,note, responseBody,  requestBody,cookieParams,responseHeader, requestHeader
//									result  = ((ApiResponseSet) r).getAttribute("requestHeader");
//									splitedResult = result.split("\n");
//									header = (splitedResult[0]).split(" ");
//									METHOD = header[0];
//									URL = header[1];
//									
//									System.out.println(METHOD+" : "+URL);
//									
//								}			
//					
//				} catch (ClientApiException e) {
//					
//					e.printStackTrace();
//				}	
//				
				
				
				
				
				
				
				
				
				
				
				 
				if (!progress.equals("running") ) {
					//api.ajaxSpiderStop(ZAP_API_KEY);
					break;
				}
			}
				
			//System.out.println("Ajax Spidering complete");
			listener.getLogger().println("Ajax Spidering complete");
			//System.out.println("*************************************** Liste des URLS trouvées ***************************************");
			listener.getLogger().println("*************************************** Liste des URLS trouvées ***************************************");
			//textAreaLog.append("phase de Spidering terminé\n");
			String nbrOfResults  =((ApiResponseElement) api.ajaxNumberOfResults()).getValue(); 
			//System.out.println("Ajax Spidering number of results : "+nbrOfResults);
			listener.getLogger().println("Ajax Spidering number of results : "+nbrOfResults);
			
				 ApiResponseList results = (ApiResponseList) (api.ajaxResults("1",String.valueOf(nbrOfResults)));
				 

							for (ApiResponse r : results.getItems()) {
								
								
								//cet appel affiche tous les attributs et leurs valeurs 
								//System.out.println(((ApiResponseSet) r).toString(1));
								//attributes : id,note, responseBody,  requestBody,cookieParams,responseHeader, requestHeader
								result  = ((ApiResponseSet) r).getAttribute("requestHeader");
								splitedResult = result.split("\n");
								header = (splitedResult[0]).split(" ");
								METHOD = header[0];
								URL = header[1];
								
								//System.out.println(METHOD+" : "+URL);
								listener.getLogger().println(METHOD+" : "+URL);
							 
			
			//System.out.println("*********************************************************************************************************");	
			
								listener.getLogger().println("*********************************************************************************************************");	
			
			
			
			
			
							}	
			
		} catch (ClientApiException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		return scanid;
}


/**
 * Affiche les résultats de la phase spidering
 * @param api
 * @param scanId
 */
public void viewSpiderResults(String scanId, BuildListener listener ){
	    	
		 try {
			 ApiResponseList results = (ApiResponseList) api.results( scanId);
			 
	
						for (ApiResponse r : results.getItems()) {
							
							//System.out.println(((ApiResponseElement) r).getValue());
							listener.getLogger().println(((ApiResponseElement) r).getValue());
						}			
			
		} catch (ClientApiException e) {
			
			e.printStackTrace();
		}
	    	
	    	
	    }

/*******************************************************************************************************************************/


/*************************************************** Scanning ******************************************************************/
public void scanURL( String url, String scanid, String scanPolicyName, BuildListener listener ){

	
		//ETAPE1 : On construit la requête
		Map<String, String> params = new HashMap<String, String>();
		params.put("apikey", zapProxyKey);
		params.put("recurse", "true");
		//params.put("scanPolicyName", PropertyLoader.getValueFromKey("SCANPOLICYNAME", "", authenticationProperties));
		params.put("scanPolicyName", scanPolicyName);
		params.put("inScopeOnly", "false");
		params.put("url", url);		

		
		//http://zap/xml/ascan/action/scan/?scanId=XXX&apikey=XXX&method=XXX&recurse=true&scanPolicyName=XXX&inScopeOnly=false&postdata=&url=target
		ApiResponse status;
		try {
			status = api.scan(params);
			
			//ETAPE2 :  Poll the status until it completes
			int progress;
			
			Map<String, String> params2 = new HashMap<String, String>(); 
			params2.put("scanid", scanid);
			while (true) {
				Thread.sleep(5000);			 
				status =api.scanStatus(params2);
				progress = Integer.parseInt(((ApiResponseElement) status).getValue());			
				//System.out.println("Active Scan progress : " + progress + "%");
				listener.getLogger().println("Active Scan progress : " + progress + "%");
				
				if (progress >= 100) {
					break;
				}
			}
			//System.out.println("Active Scan complete");
			listener.getLogger().println("Active Scan complete");
			
			String  nbrAlerts=api.numberOfAlerts("").toString(2);
			//System.out.println("Alerts number = " + nbrAlerts );	
			listener.getLogger().println("Alerts number = " + nbrAlerts );	
			
			
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		

		
	}

public void scanURLAsUser(String url, String scanid, String contextid,String userid, String recurse,String ScanPolicyName, BuildListener listener  ) {


	//ETAPE1 : On construit la requête	
 	ApiResponse status;
	try {
		status = api.scanAsUser(zapProxyKey, url, contextid, userid, recurse, ScanPolicyName);
		
		//ETAPE2 :  Poll the status until it completes
		int progress;
		
		Map<String, String> params2 = new HashMap<String, String>(); 
		params2.put("scanid", scanid);
		while (true) {
			Thread.sleep(5000);			 
			status =api.scanStatus(params2);
			progress = Integer.parseInt(((ApiResponseElement) status).getValue());			
			//System.out.println("Active Scan progress : " + progress + "%");
			listener.getLogger().println("Active Scan progress : " + progress + "%");
			
			if (progress >= 100) {
				break;
			}
		}
		//System.out.println("Active Scan complete");
		listener.getLogger().println("Active Scan complete");
		String  nbrAlerts=api.numberOfAlerts("").toString(2);
		//System.out.println("Alerts number = " + nbrAlerts );	
		listener.getLogger().println("Alerts number = " + nbrAlerts );	
		
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (InterruptedException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	


	
	
}


/*******************************************************************************************************************************/


/*************************************************** Reporting ******************************************************************/
public void saveReport(String xmlReportPath, BuildListener listener) {
		 

		byte[] xmlReportBytes;
		try {
			xmlReportBytes =  api.xmlreport(zapProxyKey);
			Files.write(Paths.get(xmlReportPath), xmlReportBytes);
			listener.getLogger().println("File [" + new File(xmlReportPath).getAbsolutePath() + "] saved");
 

		} catch (ClientApiException e) {
			 
			e.printStackTrace();
		} catch (IOException e) {
			 
			e.printStackTrace();
		}

	}



/**************************** ForcedUser.java ****************************************************/

public void isForcedUserModeEnabled(BuildListener listener ) {
	
	
	ApiResponse status;
	try {
		status = api.isForcedUserModeEnabled();
		//System.out.println(((ApiResponseElement) status).getValue());
		listener.getLogger().println(((ApiResponseElement) status).getValue());
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	
	 
}

public void getForcedUser(String contextid, BuildListener listener)  {
	ApiResponse status;
	try {
		status = api.getForcedUser(contextid);
		//System.out.println(((ApiResponseElement) status).getValue());
		listener.getLogger().println(((ApiResponseElement) status).getValue());
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	

}

public void  setForcedUser(String contextid, String userid, BuildListener listener )   {
	
	ApiResponse status;
	try {
		status = api.setForcedUser(zapProxyKey,contextid,userid);
		//System.out.println(((ApiResponseElement) status).getValue());
		listener.getLogger().println(((ApiResponseElement) status).getValue());
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 
}

public void setForcedUserModeEnabled( boolean bool, BuildListener listener)  {
	
	ApiResponse status;
	try {
		status = api.setForcedUserModeEnabled(zapProxyKey,bool);
		//System.out.println(((ApiResponseElement) status).getValue());
		listener.getLogger().println(((ApiResponseElement) status).getValue());
	} catch (ClientApiException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	 
}




/*******************************************************************************************************************************/
	
	public void enableAllScanner(String scanpolicyname, BuildListener listener ){
		//String scanpolicyname=PropertyLoader.getValueFromKey("SCANPOLICYNAME", "", authenticationProperties);
		try {
			ApiResponse status= api.enableAllScanners(zapProxyKey, scanpolicyname);
			
			//System.out.println(((ApiResponseElement) status).getValue());
			listener.getLogger().println(((ApiResponseElement) status).getValue());
			
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void PassiveScanEnableAllScanner( BuildListener listener){
		
		try {
			ApiResponse status= api.PsEnableAllScanners(zapProxyKey);
			
			//System.out.println(((ApiResponseElement) status).getValue());
			listener.getLogger().println(((ApiResponseElement) status).getValue());
			
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	public void PassiveScanDisableAllScanner( BuildListener listener ){
		 
		try {
			ApiResponse status= api.PsDisableAllScanners(zapProxyKey);
			
			//System.out.println(((ApiResponseElement) status).getValue());
			listener.getLogger().println(((ApiResponseElement) status).getValue());
			
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	
	
	public void startZAPAsUser( String url, String contextid, String userid, String maxchildren,String ScanPolicyName, BuildListener listener)  {

	 
			    System.out.println("######################### phase de spidering ######################### ");					 
				String scanid=spiderAsUserURL(url,contextid, userid, maxchildren, listener);
				
				System.out.println("######################### Résultats de spidering ######################### ");
				 viewSpiderResults(scanid, listener);
				System.out.println("########################################################################## ");
				 
				// scan
				System.out.println("######################### phase de scan ######################### ");				 
				scanURLAsUser(url, scanid, contextid, userid, "true", ScanPolicyName, listener);
				 
				// saveReport
				System.out.println("######################### Sauvegarde du rapport ######################### ");
				//textAreaLog.append("######################### Sauvegarde du rapport brute (XML) ######################### "+ "\n");
				saveReport("templates/test.xml", listener);

				// stop ZAProxy
				System.out.println("######################### Arrêt du daemon ZAP ######################### ");
	
			 
			 
	
 }

	public void startZAP(String url,  String maxchildren, String scanPolicyName, BuildListener listener)  {

		 
		    System.out.println("######################### phase de spidering ######################### ");			
			String scanid=spiderURL(url , maxchildren, listener);
			
			System.out.println("######################### Résultats de spidering ######################### ");
			 viewSpiderResults(scanid, listener);
			System.out.println("########################################################################## ");
			 
			// scan
			System.out.println("######################### phase de scan ######################### ");				 
			scanURL( url, scanid, scanPolicyName, listener);
			 
			// saveReport
			System.out.println("######################### Sauvegarde du rapport ######################### ");			 
			saveReport("test.xml", listener);

			// stop ZAProxy
			System.out.println("######################### Arrêt du daemon ZAP ######################### ");

		 
				
		 

}
	
	
	
	/**
	 * Shuts down ZAP
	 */
	public void  stopZap(String apikey, BuildListener listener )   {
		
		try {
			ApiResponse status = api.shutdown(zapProxyKey);
			listener.getLogger().println(((ApiResponseElement) status).getValue());
			
		} catch (ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}	
	

}
