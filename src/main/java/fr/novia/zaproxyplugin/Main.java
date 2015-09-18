package fr.novia.zaproxyplugin;
import java.io.File;
import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApiException;

import fr.novia.zaproxyplugin.utilities.PropertyLoader;

 

public class Main {

	public static void main(String[] args) {
		
		boolean useProxy= true;
		boolean auth=true;
		
		String webProxyProperties=new File(".").getAbsolutePath()+"/webproxy.properties";
		String authenticationProperties=new File(".").getAbsolutePath()+"/authentication.properties";
		String zapProperties=new File(".").getAbsolutePath()+"/zap.properties";		
		
		
		 
		String URL=PropertyLoader.getValueFromKey("targetURL", "", authenticationProperties);	
		String INCLUDEURL=PropertyLoader.getValueFromKey("INCLUDEURL", "", authenticationProperties);
		String EXCLUDEURL=PropertyLoader.getValueFromKey("EXCLUDEURL", "", authenticationProperties);	
		String contextName=PropertyLoader.getValueFromKey("CONTEXTNAME", "", authenticationProperties);
		String scanPolicyName=PropertyLoader.getValueFromKey("SCANPOLICYNAME", "", authenticationProperties);
		// Setup the authentication method
		
		String scriptName=PropertyLoader.getValueFromKey("scriptName", "", authenticationProperties);
		String LoginUrl = PropertyLoader.getValueFromKey("loginUrl", "", authenticationProperties); 
		String postData = PropertyLoader.getValueFromKey("Post data without credentials", "", authenticationProperties);
		String Cookie=PropertyLoader.getValueFromKey("cookie", "", authenticationProperties);
		String loggedInIndicator =PropertyLoader.getValueFromKey("loggedInIndicator", "", authenticationProperties);
		String loggedOutIndicator =PropertyLoader.getValueFromKey("loggedOutIndicator", "", authenticationProperties); 
		String user = PropertyLoader.getValueFromKey("user", "User Test", authenticationProperties); 
		String username = PropertyLoader.getValueFromKey("username", "ZAP", authenticationProperties); 
		String password = PropertyLoader.getValueFromKey("password", "ZAP", authenticationProperties); 
		
		String userid="";
		
	
		

		String ZAP_ADDRESS = PropertyLoader.getValueFromKey("ZAPHOST", "10.107.2.102", zapProperties);
		String ZAP_PORT = PropertyLoader.getValueFromKey("ZAPPORT", "8080", zapProperties);
		String ZAP_API_KEY =PropertyLoader.getValueFromKey("ZAPAPIKEY","2q0ap4er4dhnlauq165mv43cht", zapProperties);
		
		CustomZapClientApi test =new CustomZapClientApi(ZAP_ADDRESS,ZAP_PORT, ZAP_API_KEY);

		
		if(useProxy)
		  test.setWebProxyDetails(webProxyProperties);
		//listAuthInformation(api);
		
		
		System.out.println(test.getContextList());
		
		
		 
		//récupère l'id du contexte si celui là est crée sinon elle le crée et retourne son id 
		String contextId=test.getContextId(contextName);
		
		
		System.out.println("-------------");
		System.out.println("ContextId : "+contextId);	
		
		if(auth == true){
		/***************** AUTHENTIFICATION ********************/
		System.out.println("-------------");
		//test.setFormBasedAuthentication(api,contextId );
		//{"error":"false","engine":"Rhino","description":"","name":"b.espaceclientv3.orange.fr.js","type":"authentication"}
		//String LoginUrl,String postData, String Cookie, String scriptName 
		test.setScriptBasedAuthentication(contextId,LoginUrl,postData, Cookie, scriptName );
		
		System.out.println("-------------");
		test.setLoggedInIndicator(contextId,loggedInIndicator);
		
		System.out.println("-------------");
		test.setLoggedOutIndicator(contextId,loggedOutIndicator) ;
		
		System.out.println("-------------");
		test.listUserConfigInformation(contextId);
		
		System.out.println("-------------");
		//String user, String username, String password
		userid=test.setUserAuthConfig(contextId,user, username, password);
		
		test.enableUser( contextId, userid);
		
		/*********************** Forced User **********************************/
		//https://groups.google.com/forum/#!topic/zaproxy-users/GRtzMJ4WJzk
		//pour que la partie ajaxSpider se fasse d'une manière authentifiée il faut activer et renseigner le ForcedUser 
		test.isForcedUserModeEnabled();
		test.setForcedUser( contextId, userid);
		test.getForcedUser(contextId);
		test.setForcedUserModeEnabled( true);
		test.isForcedUserModeEnabled();
		
		
		
		/*********************************************************************/
		
		}
		
		
		/************************ PREPARATION DU SCANNER **********************/
		
		test.includeInContext(INCLUDEURL,contextName);	
		//test.includeInContext(api, "https://webmail.orange.fr/");
		
		if(!EXCLUDEURL.equals("")){
			test.excludeFromContext(EXCLUDEURL,contextName);
		}
		
		test.enableAllScanner(scanPolicyName );
		
		
		/*********************************************************************/
		test.setPolicyAttackStrength("0", "HIGH", scanPolicyName);
		test.setPolicyAttackStrength( "1", "HIGH", scanPolicyName);
		test.setPolicyAttackStrength("2", "HIGH", scanPolicyName);
		test.setPolicyAttackStrength("3", "HIGH", scanPolicyName);
		test.setPolicyAttackStrength( "4", "HIGH", scanPolicyName);
		
		/*********************************************************************/
		test.setPolicyAlertThreshold( "0", "HIGH", scanPolicyName);
		test.setPolicyAlertThreshold( "1", "HIGH", scanPolicyName);
		test.setPolicyAlertThreshold( "2", "HIGH", scanPolicyName);
		test.setPolicyAlertThreshold( "3", "HIGH", scanPolicyName);
		test.setPolicyAlertThreshold( "4", "HIGH", scanPolicyName);
		
		/*********************************************************************/
		test.setOptionPostForm( true);
		test.setOptionProcessForm( true);	
		test.setOptionHandleODataParametersVisited(true);
		test.setOptionShowAdvancedDialog(true);
		
		test.setOptionParseComments(true);
		test.setOptionParseRobotsTxt(true);
		test.setOptionParseSitemapXml(true);
		
		/*********************************************************************/
		
		
		//test.PassiveScanDisableAllScanner();
		test.PassiveScanEnableAllScanner();
		
		String scanid ;
		
		
		
		/********** AJAX SPIDERING *********************/
	
	    //scanid=test.ajaxSpiderURL(URL, "true");
		
		
		/**********  SPIDERING *********************/
	
			 
			if(auth==true){
			scanid=test.spiderAsUserURL(URL, contextId, userid, "100");
			
			}
			else
			scanid=test.spiderURL(URL,  "-1");
			
			System.out.println("\n######################### Résultats de spidering ######################### ");
			test.viewSpiderResults(scanid);
			System.out.println("\n########################################################################## ");
			
		
	 
		//test.startZAPAsUser(api,URL, contextId, userid, "100",scanPolicyName) ;
		//test.startZAP(api,URL,  "100");
		
		
		
		
		

	}

}
