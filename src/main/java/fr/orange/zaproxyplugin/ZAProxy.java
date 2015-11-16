
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


package fr.orange.zaproxyplugin;
 
import hudson.Extension;
import hudson.FilePath;
import hudson.FilePath.FileCallable;
import hudson.model.AbstractDescribableImpl;
import hudson.model.BuildListener;
import hudson.model.Descriptor;
import hudson.remoting.VirtualChannel;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import fr.orange.zaproxyplugin.CustomZapClientApi;
import 	fr.orange.zaproxyplugin.ZAProxyBuilder;
import  fr.orange.zaproxyplugin.report.ZAPreport;
import  fr.orange.zaproxyplugin.report.ZAPreportCollection;
import  fr.orange.zaproxyplugin.report.ZAPscannersCollection;
import fr.orange.zaproxyplugin.utilities.HttpUtilities;
import  fr.orange.zaproxyplugin.utilities.ProxyAuthenticator;
import fr.orange.zaproxyplugin.utilities.SSHConnexion;
import fr.orange.zaproxyplugin.utilities.SecurityTools;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.xml.parsers.ParserConfigurationException;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.tools.ant.BuildException;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.xml.sax.SAXException;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ApiResponseSet;
import org.zaproxy.clientapi.core.ClientApiException;

 

/**
 * Contains methods to start and execute ZAProxy. Members variables are bind to
 * the config.jelly placed to fr/novia/zaproxyplugin/ZAProxy
 * Cette classe permet de lancer ZAP, les noms des attributs de la classe doivent être identiques à ceux renseignés dans le fichier config.jelly situé à fr/orange/zapkins/ZAProxy
 * 
 * @authors  Abdellah AZOUGARH
 *
 */
public class ZAProxy extends AbstractDescribableImpl<ZAProxy> implements Serializable {

	/**
	 * 
	 */
	
	public final static boolean debug = true;
	
	private static final long serialVersionUID = 946509532597271579L;
	private final String user = "ZAP USER";
	public static final String FILE_SESSION_EXTENSION = ".session";
	public static final String FILE_SCRIPTS_EXTENSION = ".scripts";
	public static final String AUTHENTICATION_SCRIPTS_LIST_FILE = "authenticationScriptsList.scripts";
	public static final String SESSIONS_LIST_FILE = "sessionsListFile.session";

	public final static String ROOT_PATH = "ZAPRProxy";
	public final String REPORTS_PATH = "reports";
	public final String SESSIONS_PATH = "sessions";
	public final static String AUTHENTICATION_SCRIPTS_PATH = "scripts";

	public static String FILE_SEPARATOR = "";

	// Les attributs possédant une visibilité Final, sont initialisé à
	// l'instantiation de la classe et ne peuvent pas être modifiés à la suite
	/** the scan mode (AUTHENTICATED/NOT_AUTHENTICATED) */
	private final String scanMode;

	/** the authentication mode (SCRIPT_BASED/FORM_BASED) */
	private final String authenticationMode;

	/** URL to attack by ZAProxy */
	private final String targetURL;

	/** Realize a url spider or not by ZAProxy */
	private final boolean spiderURL;

	/** Realize a url AjaxSpider or not by ZAProxy */
	private final boolean ajaxSpiderURL;

	/** Realize a url scan or not by ZAProxy */
	private final boolean scanURL;

	/** Authentication script name */
	private final String scriptName;

	/** loggin url **/
	private final String loginUrl;

	/** context Name **/
	private final String contextName;

	/** Included url in scan **/
	private final String includedUrl;

	/** Exclude url from scan **/
	private final String excludedUrl;

	/** FORM : logged in indication */
	private final String formLoggedInIndicator;

	/** FORM : logged out indicator */
	private final String formLoggedOutIndicator;

	/** SCRIPT : logged in indication */
	private final String scriptLoggedInIndicator;

	/** SCRIPT : logged out indicator */
	private final String scriptLoggedOutIndicator;

	/** post data used to request the login URL without credentials */
	private final String postData;

	/** Authentication information for conduct spider as a user */

	/** user name for authentication (FormBasedAuthentication) */
	private final String formUsername;

	/** Password for the defined user */
	private final String formPassword;

	/** user name for authentication (scriptBasedAuthentication) */
	private final String scriptUsername;

	/** Password for the defined user */
	private final String scriptPassword;

	/** user name parameter user for authentication */
	private final String usernameParameter;

	/** Password parameter used for the defined user */
	private final String passwordParameter;

	/** Save reports or not */
	private final boolean saveReports;

	/**
	 * List of chosen format for reports. ArrayList because it needs to be
	 * Serializable (whereas List is not Serializable)
	 */
	private final ArrayList<String> chosenFormats;

	/**
	 * List of chosen scanners for audits. ArrayList because it needs to be
	 * Serializable (whereas List is not Serializable)
	 */
	private final ArrayList<String> chosenScanners;

	/** Filename for ZAProxy reports. It can contain a relative path. */
	private final String filenameReports;

	/**
	 * The file policy to use for the scan. It contains only the policy name
	 * (without extension)
	 */
	private final String chosenPolicy;
//	

	/**
	 * Liste des urls authorisées à être scannées
	 */
	private String authorizedURL;
	
	/*
	 * Type de protocole de connexion au serveur ZAP
	 */
	private  String protocol;
	/**
	 *  stop ZAP at the end of scan 
	 */
	private  boolean stopZAPAtEnd;

	/** Host configured when ZAProxy is used as proxy */
	private String zapProxyHost;
	
	/** Port configured when ZAProxy is used as proxy */
	private int zapProxyPort;
	
	/** the secret API key when ZAProxy is used */
	private String zapProxyKey;
	
	/** répertoire d'installation du moteur ZAP Proxy */
	private String zapProxyDirectory;

	/** Id of the newly created context */
	private String contextId;
	
	/** Id of the newly created user */
	private String userId;
	
	/** Id of the newly created scan */
	private String scanId;

		@DataBoundConstructor
		public ZAProxy( ArrayList<String> chosenScanners, String scanMode,
				String authenticationMode,   
				String targetURL, boolean spiderURL, boolean ajaxSpiderURL, boolean scanURL,  
				String scriptName, String loginUrl, String contextName, String includedUrl, String excludedUrl,
				String formLoggedInIndicator, String formLoggedOutIndicator, String scriptLoggedInIndicator,
				String scriptLoggedOutIndicator, String postData, String usernameParameter, String passwordParameter,
				String formUsername, String formPassword, String scriptUsername, String scriptPassword,
				 boolean scanURLAsUser, boolean saveReports, ArrayList<String> chosenFormats,
				String filenameReports,    String chosenPolicy,
				String contextId, String userId, String scanId) {
			
			
			super();			
			this.authorizedURL=ZAProxyBuilder.DESCRIPTOR.getAuthorizedURLs();
			this.protocol=ZAProxyBuilder.DESCRIPTOR.getDefaultProtocol();
			this.zapProxyHost = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultHost();			
			this.zapProxyKey = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultApiKey();
			this.zapProxyDirectory=ZAProxyBuilder.DESCRIPTOR.getZapDefaultDirectory();
			this.stopZAPAtEnd = ZAProxyBuilder.DESCRIPTOR.isStopZAPAtEnd();		
			this.spiderURL = ZAProxyBuilder.DESCRIPTOR.isSpiderURL();
			this.ajaxSpiderURL = ZAProxyBuilder.DESCRIPTOR.isAjaxSpiderURL();
			this.scanURL = ZAProxyBuilder.DESCRIPTOR.isScanURL();
			
			this.chosenScanners = chosenScanners;
			this.scanMode = scanMode;
			this.authenticationMode = authenticationMode;				
			this.targetURL = targetURL;
			this.scriptName = scriptName;
			this.loginUrl = loginUrl;
			this.contextName = contextName;
			this.includedUrl = includedUrl;
			this.excludedUrl = excludedUrl;
			this.formLoggedInIndicator = formLoggedInIndicator;
			this.formLoggedOutIndicator = formLoggedOutIndicator;
			this.scriptLoggedInIndicator = scriptLoggedInIndicator;
			this.scriptLoggedOutIndicator = scriptLoggedOutIndicator;
			this.postData = postData;
			this.usernameParameter = usernameParameter;
			this.passwordParameter = passwordParameter;
			this.formUsername = formUsername;
			this.formPassword = formPassword;
			this.scriptUsername = scriptUsername;
			this.scriptPassword = scriptPassword;
			this.saveReports = saveReports;
			this.chosenFormats = chosenFormats;
			this.filenameReports = filenameReports;
			this.chosenPolicy = chosenPolicy;
			this.contextId = contextId;
			this.userId = userId;
			this.scanId = scanId;
			System.out.println(this.toString());
		}

	@Override
	public String toString() {
		String s = "";

		s += "--------------------------------------------------";
		s += "zapProxyHost [" + zapProxyHost + "]\n";
		s += "zapProxyPort [" + zapProxyPort + "]\n";
		s += "saveReports [" + saveReports + "]\n";
		s += "chosenFormats [" + chosenFormats + "]\n";
		s += "filenameReports [" + filenameReports + "]\n";
		s += "--------------------------------------------------";
		s += "targetURL [" + targetURL + "]\n";
		s += "chosenPolicy [" + chosenPolicy + "]\n";
		s += "Authentication Script Name [" + scriptName + "]\n";
		s += "loginUrl [" + loginUrl + "]\n";
		s += "post Data [" + postData + "]\n";
		s += "formLoggedInIndicator [" + formLoggedInIndicator + "]\n";
		s += "formLoggedOutIndicator [" + formLoggedOutIndicator + "]\n";
		s += "scriptLoggedInIndicator [" + scriptLoggedInIndicator + "]\n";
		s += "scriptLoggedOutIndicator [" + scriptLoggedOutIndicator + "]\n";
		s += "--------------------------------------------------";
		s += "spiderURL [" + spiderURL + "]\n";
		s += "ajaxSpiderURL [" + ajaxSpiderURL + "]\n";
		s += "scanURL [" + scanURL + "]\n";
		s += "--------------------------------------------------";
		s += "scriptUsername [" + scriptUsername + "]\n";
		s += "formUsername [" + formUsername + "]\n";
		s += "--------------------------------------------------";

		return s;
	}

	// Overridden for better type safety.
	// If your plugin doesn't really define any property on Descriptor,
	// you don't have to do this.
	@Override
	public ZAProxyDescriptorImpl getDescriptor() {
		return (ZAProxyDescriptorImpl) super.getDescriptor();
	}

	/**
	 * @return the user
	 */
	public String getUser() {
		return user;
	}

	/**
	 * @return the fileSessionExtension
	 */
	public static String getFileSessionExtension() {
		return FILE_SESSION_EXTENSION;
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
	public int getZapProxyPort() {
		return zapProxyPort;
	}

	/**
	 * @return the zapProxyKey
	 */
	public String getZapProxyKey() {
		return zapProxyKey;
	}

	/**
	 * @return the zapProxyDirectory
	 */
	public String getZapProxyDirectory() {
		return zapProxyDirectory;
	}

	/**
	 * @return the formUsername
	 */
	public String getFormUsername() {
		return formUsername;
	}

	/**
	 * @return the formPassword
	 */
	public String getFormPassword() {
		return formPassword;
	}

	/**
	 * @return the scriptUsername
	 */
	public String getScriptUsername() {
		return scriptUsername;
	}

	/**
	 * @return the scriptPassword
	 */
	public String getScriptPassword() {
		return scriptPassword;
	}

	/**
	 * @return the usernameParameter
	 */
	public String getUsernameParameter() {
		return usernameParameter;
	}

	/**
	 * @return the passwordParameter
	 */
	public String getPasswordParameter() {
		return passwordParameter;
	}

	/**
	 * @return the scanId
	 */
	public String getScanId() {
		return scanId;
	}

	/**
	 * @param scanId
	 *            the scanId to set
	 */
	public void setScanId(String scanId) {
		this.scanId = scanId;
	}

	/**
	 * @return the scriptName
	 */
	public String getScriptName() {
		return scriptName;
	}

	/**
	 * @return the formLoggedInIndicator
	 */
	public String getFormLoggedInIndicator() {
		return formLoggedInIndicator;
	}

	/**
	 * @return the formLoggedOutIndicator
	 */
	public String getFormLoggedOutIndicator() {
		return formLoggedOutIndicator;
	}

	/**
	 * @return the scriptLoggedInIndicator
	 */
	public String getScriptLoggedInIndicator() {
		return scriptLoggedInIndicator;
	}

	/**
	 * @return the scriptLoggedOutIndicator
	 */
	public String getScriptLoggedOutIndicator() {
		return scriptLoggedOutIndicator;
	}

	/**
	 * @return the postData
	 */
	public String getPostData() {
		return postData;
	}
/**
 * 
 * @return the targetURL
 */
	public String getTargetURL() {
		return targetURL;
	}

	/**
	 * @return the contextName
	 */
	public String getContextName() {
		return contextName;
	}

	/**
	 * @return the includedUrl
	 */
	public String getIncludedUrl() {
		return includedUrl;
	}

	/**
	 * @return the excludedUrl
	 */
	public String getExcludedUrl() {
		return excludedUrl;
	}

	public boolean getSpiderURL() {
		return spiderURL;
	}

	public boolean getAjaxSpiderURL() {
		return ajaxSpiderURL;
	}

	public boolean getScanURL() {
		return scanURL;
	}

	public boolean getSaveReports() {
		return saveReports;
	}

	public List<String> getChosenFormats() {
		return chosenFormats;
	}

	/**
	 * @return the chosenScanners
	 */
	public ArrayList<String> getChosenScanners() {
		return chosenScanners;
	}

	public String getFilenameReports() {
		return filenameReports;
	}

	public String getChosenPolicy() {
		return chosenPolicy;
	}
	
	public String getLoginUrl() {
		return loginUrl;
	}

	/**
	 * @return the contextId
	 */
	public String getContextId() {
		return contextId;
	}

	/**
	 * @return the userId
	 */
	public String getUserId() {
		return userId;
	}

	/**
	 * @return the scanMode
	 */
	public String getScanMode() {
		return scanMode;
	}

	/**
	 * @return the authenticationMode
	 */
	public String getAuthenticationMode() {
		return authenticationMode;
	}

	/**
	 * @return the fILE_SEPARATOR
	 */
	public static String getFILE_SEPARATOR() {
		return FILE_SEPARATOR;
	}

	/**
	 * @return the stopZAPAtEnd
	 */
	public boolean isStopZAPAtEnd() {
		return stopZAPAtEnd;
	}

	/**
	 * @return the protocol
	 */
	public String getProtocol() {
		return protocol;
	}

	/**
	 * @param protocol the protocol to set
	 */
	public void setProtocol(String protocol) {
		this.protocol = protocol;
	}

	/**
	 * @param stopZAPAtEnd the stopZAPAtEnd to set
	 */
	public void setStopZAPAtEnd(boolean stopZAPAtEnd) {
		this.stopZAPAtEnd = stopZAPAtEnd;
	}

	/**
	 * @param fILE_SEPARATOR
	 *            the fILE_SEPARATOR to set
	 */
	public static void setFILE_SEPARATOR(String fILE_SEPARATOR) {
		FILE_SEPARATOR = fILE_SEPARATOR;
	}

	/**
	 * @param contextId
	 *            the contextId to set
	 */
	public void setContextId(String contextId) {
		this.contextId = contextId;
	}

	/**
	 * @param userId
	 *            the userId to set
	 */
	public void setUserId(String userId) {
		this.userId = userId;
	}


	public boolean executeZAP(FilePath workspace, BuildListener listener) {
		
		
		listener.getLogger().println("targetURL : " + targetURL);
		listener.getLogger().println("authorizedURL : " + authorizedURL);
		
		if(!SecurityTools.isScannable(targetURL, authorizedURL)){
			
			throw new BuildException("L'url ciblée n'est pas autorisée, veuillez vous rapprochez de l'équipe sécurité pour justifier votre choix");
		}	

		CustomZapClientApi zapClientAPI = new CustomZapClientApi(protocol,zapProxyHost, zapProxyPort, zapProxyKey, listener,debug);	 
		
		boolean buildSuccess = true;

		// Try/catch here because I need to stopZAP in finally block and for
		// that,

		try {

			/*
			 * ======================================================= | ZAP FILE PATH SEPARATOR | =======================================================
			 */

			String zapHomeDirectory = zapClientAPI.getZapHomeDirectory();
			listener.getLogger().println("zapHomeDirectory : " + zapHomeDirectory);
			if (zapHomeDirectory.startsWith("/")) {
				setFILE_SEPARATOR("/");
			} else {
				setFILE_SEPARATOR("\\");
			}

			
			executeZAPSessionNotLoaded( workspace,  listener);
			
			/*
			 * ======================================= ACTIONS POST AUDIT ======================================================
			 */

			/*
			 * ======================================================= | SAVE REPORTS | =======================================================
			 */
			if (saveReports) {
				// Generates reports for all formats selected
				for (String format : chosenFormats) {

					saveReport(ROOT_PATH + getFILE_SEPARATOR() + REPORTS_PATH, filenameReports, format, listener,
							workspace, zapClientAPI);
				}
			}



			// }
		} catch (Exception e) {
			listener.error(ExceptionUtils.getStackTrace(e));
			buildSuccess = false;
		} finally {

			if (stopZAPAtEnd) {				

				stopZAP(zapClientAPI, listener);
			}

			buildSuccess = true;

		}
		return buildSuccess;
	}

	private void executeZAPSessionNotLoaded(FilePath workspace, BuildListener listener) throws IOException {
		
		CustomZapClientApi zapClientAPI = new CustomZapClientApi( zapProxyHost, zapProxyPort, zapProxyKey, listener, debug);		 
		
		listener.getLogger().println("Skip loadSession");

		/*
		 * ======================================================= | SET Up CONTEXT | =======================================================
		 */

		setUpContexte(zapClientAPI, listener);
		
		/*
		 * ======================================================= | SET Up OPTIONS | =======================================================
		 */
		setUpOptions(zapClientAPI, listener);
		/*
		 * ======================================================= | SET UP SCANNER | =======================================================
		 */
		setUpScanners(zapClientAPI, listener);
		
		
		
		switch (scanMode) {

		case "NOT_AUTHENTICATED": {
			listener.getLogger().println("SCANMOD : NOT_AUTHENTICATED");
			/*
			 * ======================================================= |
			 * SPIDER URL |
			 * =======================================================
			 */
			if (spiderURL) {
				listener.getLogger().println("Spider the site [" + targetURL + "] without credentials");
				spiderURL(targetURL, zapClientAPI, listener);
			} else {
				listener.getLogger().println("Skip spidering the site [" + targetURL + "]");
			}

			/*
			 * ======================================================= |
			 * AJAX SPIDER URL |
			 * =======================================================
			 */
			if (ajaxSpiderURL) {
				listener.getLogger().println("Ajax Spider the site [" + targetURL + "] without credentials");
				ajaxSpiderURL(targetURL, listener, zapClientAPI);
			} else {
				listener.getLogger().println("Skip Ajax spidering the site [" + targetURL + "]");
			}
			/*
			 * ======================================================= |
			 * VIEW SPIDER RESULTS |
			 * =======================================================
			 */
			if (spiderURL || ajaxSpiderURL) {
				zapClientAPI.viewSpiderResults(scanId, listener);
			}
			/*
			 * ======================================================= |
			 * SCAN URL |
			 * =======================================================
			 */
			if (scanURL) {
				listener.getLogger().println("Scan the site [" + targetURL + "]");
				scanURL(targetURL, listener, zapClientAPI);
			} else {
				listener.getLogger().println("Skip scanning the site [" + targetURL + "]");
			}
			break;
		}

		case "AUTHENTICATED": {

			listener.getLogger().println("SCANMOD : AUTHENTICATED");
			/*
			 * =============================== MODE AVEC AUTHENTIFICATION =========================================================
			 * =====
			 */

			switch (authenticationMode) {

			case "SCRIPT_BASED": {
				listener.getLogger().println("AUTHENTICATION_MOD :  : SCRIPT_BASED");
				setUpScriptBasedAuthenticationConf(zapClientAPI, listener);
				break;
			}

			case "FORM_BASED": {
				listener.getLogger().println("AUTHENTICATION_MOD :  : FORM_BASED");
				setUpFormBasedAuthenticationConf(zapClientAPI, listener);
				break;
			}

			}
			
			/*
			 * ======================================================= |
			 * SPIDER URL AS USER |
			 * =======================================================
			 */
			if (spiderURL) {

				listener.getLogger().println("Spider the site [" + targetURL + "] As User [" + userId + "]");

				spiderURLAsUser(targetURL, listener, zapClientAPI, this.getContextId(), this.getUserId());

			} else {
				listener.getLogger()
						.println("Skip spidering the site [" + targetURL + "] As User [" + userId + "]");
			}

			/*
			 * ======================================================= |
			 * AJAX SPIDER URL AS USER |
			 * =======================================================
			 */
			if (ajaxSpiderURL) {
				listener.getLogger()
						.println("Ajax Spider the site [" + targetURL + "] As User [" + userId + "]");
				ajaxSpiderURL(targetURL, listener, zapClientAPI);
			} else {
				listener.getLogger()
						.println("Skip Ajax spidering the site [" + targetURL + "] As User [" + userId + "]");
			}

			/*
			 * ======================================================= |
			 * VIEW SPIDER RESULTS |
			 * =======================================================
			 */

			if (spiderURL || ajaxSpiderURL) {
				zapClientAPI.viewSpiderResults(scanId, listener);
			}

			/*
			 * ======================================================= |
			 * SCAN URL As USER |
			 * =======================================================
			 */
			if (scanURL) {
				listener.getLogger().println("Scan the site [" + targetURL + "] As user [" + userId + "]");
				scanURLAsUser(targetURL, listener, zapClientAPI);

			} else {
				listener.getLogger()
						.println("Skip scanning the site [" + targetURL + "] As User [" + userId + "]");
			}

			break;
		}



		}				

	}

	/**
	 * Test if the test type names match (for marking the radio button).
	 * 
	 * @param testTypeName
	 *            The String representation of the test type.
	 * @return Whether or not the test type string matches.
	 */
	public String isScanMode(String testTypeName) {
		return this.scanMode.equalsIgnoreCase(testTypeName) ? "true" : "";
	}

	public String isAuthenticationMode(String testTypeName) {
		return this.authenticationMode.equalsIgnoreCase(testTypeName) ? "true" : "";
	}

	/**
	 * @param zapProxyPort the zapProxyPort to set
	 */
	public void setZapProxyPort(int zapProxyPort) {
		this.zapProxyPort = zapProxyPort;
	}

	/**
	 * Generates security report for one format. Reports are saved into build's
	 * workspace.
	 * 
	 * @param reportFormat
	 *            the format of the report
	 * @param listener
	 *            the listener to display log during the job execution in
	 *            jenkins
	 * @param workspace
	 *            a {@link FilePath} representing the build's workspace
	 * @param clientApi
	 *            the ZAP client API to call method
	 * @throws ClientApiException
	 * @throws IOException
	 */
	private void saveReport(String pathReports, String filenameReports, String format, BuildListener listener,
			FilePath workspace, CustomZapClientApi clientApi) throws IOException, ClientApiException {

		final String fullFileName = pathReports + getFILE_SEPARATOR() + format + getFILE_SEPARATOR() + filenameReports
				+ "." + format;
		File reportsFile = new File(workspace.getRemote(), fullFileName);

		switch (format) {

		case "xml": {
			 
				FileUtils.writeByteArrayToFile(reportsFile, clientApi.generateXmlReport());
				listener.getLogger().println("File [" + reportsFile.getAbsolutePath() + "] saved");
				break;
			 

		}

		case "html": {
			 
				FileUtils.writeByteArrayToFile(reportsFile, clientApi.generateHtmlReport());
				listener.getLogger().println("File [" + reportsFile.getAbsolutePath() + "] saved");
				break;
			 

		}

		}

	}

	public boolean saveSession(String name, String overwrite, BuildListener listener, CustomZapClientApi clientApi) {

		String status = clientApi.saveSession(name, overwrite, listener);

		if (status.equals("OK"))
			return true;

		return false;
	}

	
	
	
	private void setUpOptions(CustomZapClientApi zapClientAPI, BuildListener listener){
		
/*********************************************************************/
		
		// on active les scans passifs
		zapClientAPI.PassiveScanEnableAllScanner(listener);
		
		zapClientAPI.setOptionPostForm(true);
		zapClientAPI.setOptionProcessForm(true);
		zapClientAPI.setOptionHandleODataParametersVisited(true);
		zapClientAPI.setOptionShowAdvancedDialog(true);

		zapClientAPI.setOptionParseComments(true);
		zapClientAPI.setOptionParseRobotsTxt(true);
		zapClientAPI.setOptionParseSitemapXml(true);

		/*********************************************************************/
	}
	
	
	
	private void setUpScanners(CustomZapClientApi zapClientAPI, BuildListener listener) {
		/************************ PREPARATION DU SCANNER **********************/

		/*********************************************************************/
		zapClientAPI.setPolicyAttackStrength("0", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAttackStrength("1", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAttackStrength("2", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAttackStrength("3", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAttackStrength("4", "HIGH", chosenPolicy);

		/*********************************************************************/
		// Ici on met le tous à OFF sinon les scanners seront activés malgé
		// l'appel de la fonction disableAllScanners()
		zapClientAPI.setPolicyAlertThreshold("0", "OFF", chosenPolicy);
		zapClientAPI.setPolicyAlertThreshold("1", "OFF", chosenPolicy);
		zapClientAPI.setPolicyAlertThreshold("2", "OFF", chosenPolicy);
		zapClientAPI.setPolicyAlertThreshold("3", "OFF", chosenPolicy);
		zapClientAPI.setPolicyAlertThreshold("4", "OFF", chosenPolicy);

		
		Map<String, String> mapScannersTypes = ZAPscannersCollection.getInstance().getMapScannersTypes();
		boolean allScanners = false;
		for (String format : chosenScanners) {

			if (mapScannersTypes.get(format).equals("ALL")) {
				allScanners = true;
			}

		}

		if (!allScanners) {
			// ETAPE 1 : on désactive tous les scanners
			zapClientAPI.disableAllScanners(chosenPolicy, listener);
			// ETAPE 1 : on active les scans voulus
			String scannerIds = "";
			for (String format : chosenScanners) {
				scannerIds = mapScannersTypes.get(format);
				zapClientAPI.enableScanners(scannerIds, listener);
				zapClientAPI.setScannerAlertThreshold(scannerIds, "HIGH", chosenPolicy);
				zapClientAPI.setScannerAttackStrength(scannerIds, "HIGH", chosenPolicy);
			}

		} else {
			zapClientAPI.enableAllScanners(chosenPolicy, listener);
			zapClientAPI.setPolicyAlertThreshold("0", "HIGH", chosenPolicy);
			zapClientAPI.setPolicyAlertThreshold("1", "HIGH", chosenPolicy);
			zapClientAPI.setPolicyAlertThreshold("2", "HIGH", chosenPolicy);
			zapClientAPI.setPolicyAlertThreshold("3", "HIGH", chosenPolicy);
			zapClientAPI.setPolicyAlertThreshold("4", "HIGH", chosenPolicy);
		}
		
	}
	

	private void setUpContexte(CustomZapClientApi zapClientAPI, BuildListener listener) {

		listener.getLogger().println(zapClientAPI.getContextList());
		// récupère l'id du contexte si celui là est crée sinon elle le crée et
		// retourne son id
		String contextId = zapClientAPI.getContextId(contextName, listener);
		setContextId(contextId);
		listener.getLogger().println("ContextId : " + contextId);

		
		zapClientAPI.includeInContext(includedUrl, contextName, listener);
		
		if (!excludedUrl.equals("")) {
			zapClientAPI.excludeFromContext(excludedUrl, contextName, listener);
		}

	}

	/**
	 * Set up all authentication details
	 * 
	 * @author Abdellah AZOUGARH
	 * @param username
	 *            user name to be used in authentication
	 * @param password
	 *            password for the authentication user
	 * @param usernameParameter
	 *            parameter define in passing username
	 * @param passwordParameter
	 *            parameter that define in passing password for the user
	 * @param loginUrl
	 *            login page url
	 * @param loggedInIdicator
	 *            indication for know its logged in
	 * @throws ClientApiException
	 * @throws InterruptedException
	 * @throws UnsupportedEncodingException
	 */
	private void setUpScriptBasedAuthenticationConf(CustomZapClientApi zapClientAPI, BuildListener listener) {

		/***************** AUTHENTIFICATION ********************/
		listener.getLogger().println("---------------------------------------");

		zapClientAPI.setScriptBasedAuthentication(contextId, scriptName, listener);

		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedInIndicator(contextId, scriptLoggedInIndicator, listener);

		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedOutIndicator(contextId, scriptLoggedOutIndicator, listener);

		listener.getLogger().println("---------------------------------------");
		zapClientAPI.listUserConfigInformation(contextId, listener);

		listener.getLogger().println("---------------------------------------");
		String userid = zapClientAPI.setUserScriptAuthConfig(contextId, user, scriptUsername, scriptPassword, listener);
		this.setUserId(userid);

		zapClientAPI.enableUser(contextId, userid, listener);

		/*********************** Forced User **********************************/
		// https://groups.google.com/forum/#!topic/zaproxy-users/GRtzMJ4WJzk
		// pour que la partie ajaxSpider se fasse d'une manière authentifiée il
		// faut activer et renseigner le ForcedUser
		zapClientAPI.isForcedUserModeEnabled(listener);
		zapClientAPI.setForcedUser(contextId, userid, listener);
		zapClientAPI.getForcedUser(contextId, listener);
		zapClientAPI.setForcedUserModeEnabled(true, listener);
		zapClientAPI.isForcedUserModeEnabled(listener);

		/*********************************************************************/

	}


	private void setUpFormBasedAuthenticationConf(CustomZapClientApi zapClientAPI, BuildListener listener) {

		/***************** AUTHENTIFICATION ********************/
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setUpFormBasedAuthentication(contextId, loginUrl, postData, usernameParameter, passwordParameter,
				listener);

		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedInIndicator(contextId, formLoggedInIndicator, listener);

		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedOutIndicator(contextId, formLoggedOutIndicator, listener);

		listener.getLogger().println("---------------------------------------");
		zapClientAPI.listUserConfigInformation(contextId, listener);

		listener.getLogger().println("---------------------------------------");
		String userid = zapClientAPI.setUserFormAuthConfig(contextId, user, formUsername, formPassword, listener);
		this.setUserId(userid);

		zapClientAPI.enableUser(contextId, userid, listener);

		/*********************** Forced User **********************************/
		// https://groups.google.com/forum/#!topic/zaproxy-users/GRtzMJ4WJzk
		// pour que la partie ajaxSpider se fasse d'une manière authentifiée il
		// faut activer et renseigner le ForcedUser
		zapClientAPI.isForcedUserModeEnabled(listener);
		zapClientAPI.setForcedUser(contextId, userid, listener);
		zapClientAPI.getForcedUser(contextId, listener);
		zapClientAPI.setForcedUserModeEnabled(true, listener);
		zapClientAPI.isForcedUserModeEnabled(listener);

		/*********************************************************************/

	}

	private void spiderURL(final String url, CustomZapClientApi zapClientAPI, BuildListener listener) {
		String scanId = zapClientAPI.spiderURL(url, "", listener);
		this.setScanId(scanId);

	}



	private void spiderURLAsUser(final String url, BuildListener listener, CustomZapClientApi zapClientAPI,
			String contextId, String userId) {

		String scanId = zapClientAPI.spiderAsUserURL(url, this.getContextId(), this.getUserId(), "0", listener);
		this.setScanId(scanId);

	}


	private void ajaxSpiderURL(final String url, BuildListener listener, CustomZapClientApi zapClientAPI) {

		zapClientAPI.ajaxSpiderURL(url, "false", listener);

	}


	private void scanURL(final String url, BuildListener listener, CustomZapClientApi zapClientAPI) {
		if (chosenPolicy == null || chosenPolicy.isEmpty()) {
			listener.getLogger().println("Scan url [" + url + "] with the policy by default");
		} else {
			listener.getLogger().println("Scan url [" + url + "] with the following policy [" + chosenPolicy + "]");
		}

		zapClientAPI.scanURL(url, this.getScanId(), chosenPolicy, listener);

	}

	private void scanURLAsUser(final String url, BuildListener listener, CustomZapClientApi zapClientAPI) {
		if (chosenPolicy == null || chosenPolicy.isEmpty()) {
			listener.getLogger().println("Scan url [" + url + "] with the policy by default As User");
		} else {
			listener.getLogger()
					.println("Scan url [" + url + "] As User with the following policy [" + chosenPolicy + "]");
		}

		zapClientAPI.scanURLAsUser(url, this.getScanId(), this.getContextId(), this.getUserId(), "true", chosenPolicy,
				listener);

	}

	/**
	 * Stop ZAproxy if it has been previously started.
	 * 
	 * @param zapClientAPI
	 *            the client API to use ZAP API methods
	 * @param listener
	 *            the listener to display log during the job execution in
	 *            jenkins
	 * @throws ClientApiException
	 */
	private void stopZAP(CustomZapClientApi zapClientAPI, BuildListener listener) {
		if (zapClientAPI != null) {
			listener.getLogger().println("Shutdown ZAProxy");
			zapClientAPI.stopZap(zapProxyKey, listener);
		} else {
			listener.getLogger().println("No shutdown of ZAP (zapClientAPI==null)");
		}
	}

	/**
	 * Descriptor for {@link ZAProxy}. Used as a singleton. The class is marked
	 * as public so that it can be accessed from views.
	 *
	 * <p>
	 * See <tt>src/main/resources/fr/ORANGE/zaproxyplugin/ZAProxy/*.jelly</tt>
	 * for the actual HTML fragment for the configuration screen.
	 */
	@Extension
	public static class ZAProxyDescriptorImpl extends Descriptor<ZAProxy> implements Serializable {

		private static final long serialVersionUID = 4028279269334325901L;
		private static final int MILLISECONDS_IN_SECOND = 1000;
		/**
		 * To persist global configuration information, simply store it in a
		 * field and call save().
		 *
		 * <p>
		 * If you don't want fields to be persisted, use <tt>transient</tt>.
		 */

		/**
		 * Map where key is the report format represented by a String and value
		 * is a ZAPreport object allowing to generate a report with the
		 * corresponding format.
		 */
		private Map<String, ZAPreport> mapFormatReport;

		/**
		 * Map where key is the scanner type represented by a String and value
		 * is a string corresponding to the scanner id known by ZAP.
		 */
		private Map<String, String> mapScannersTypes;

		/** Represents the build's workspace */
		private FilePath workspace;

		/**
		 * In order to load the persisted global configuration, you have to call
		 * load() in the constructor.
		 */
		public ZAProxyDescriptorImpl() {
			mapFormatReport = ZAPreportCollection.getInstance().getMapFormatReport();
			mapScannersTypes = ZAPscannersCollection.getInstance().getMapScannersTypes();

			load();
		}

		@Override
		public String getDisplayName() {
			return null;
		}

		public Map<String, ZAPreport> getMapFormatReport() {
			return mapFormatReport;
		}

		public Map<String, String> getMapScannersTypes() {
			return mapScannersTypes;
		}

		public List<String> getAllFormats() {
			return new ArrayList<String>(mapFormatReport.keySet());
		}

		public List<String> getAllScanners() {
			// On supprime l'élément "ALL SCANNERS" et on le remet au début.
			ArrayList<String> tab = new ArrayList<String>(mapScannersTypes.keySet());
			tab.remove(tab.indexOf("ALL SCANNERS"));
			tab.add(0, "ALL SCANNERS");
			return tab;
		}

		public void setWorkspace(FilePath ws) {
			this.workspace = ws;
		}	
		
		
		public FormValidation doCheckTargetURL(@QueryParameter("targetURL") final String targetURL) {
			
			
			String  authorizedURL=ZAProxyBuilder.DESCRIPTOR.getAuthorizedURLs();
			
			if(!SecurityTools.isScannable(targetURL, authorizedURL)){
				
				return FormValidation.error("URL hors scope (non authorisée)");
			}
			
			return FormValidation.ok();
			
		
		}

		/**
		 * Performs on-the-fly validation of the form field 'filenameReports'.
		 *
		 * @param filenameReports
		 *            This parameter receives the value that the user has typed.
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 *         <p>
		 *         Note that returning {@link FormValidation#error(String)} does
		 *         not prevent the form from being saved. It just means that a
		 *         message will be displayed to the user.
		 */
		public FormValidation doCheckFilenameReports(@QueryParameter("filenameReports") final String filenameReports) {
			if (filenameReports.isEmpty())
				return FormValidation.error("Ce champ est obligatoire");
			if (!FilenameUtils.getExtension(filenameReports).isEmpty())
				return FormValidation.warning("L'extension du fichier n'est pas nécessaire !");
			return FormValidation.ok();
		}

		/**
		 * Performs on-the-fly validation of the form field
		 * 'filenameSaveSession'.
		 * <p>
		 * If the user wants to save session whereas a session is already
		 * loaded, the relative path to the saved session must be different from
		 * the relative path to the loaded session.
		 *
		 * @param filenameLoadSession
		 *            Parameter to compare with filenameSaveSession.
		 * @param filenameSaveSession
		 *            This parameter receives the value that the user has typed.
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 *         <p>
		 *         Note that returning {@link FormValidation#error(String)} does
		 *         not prevent the form from being saved. It just means that a
		 *         message will be displayed to the user.
		 */
		public FormValidation doCheckFilenameSaveSession(
				@QueryParameter("filenameLoadSession") final String filenameLoadSession,
				@QueryParameter("filenameSaveSession") final String filenameSaveSession) {
			// Contains just the name of the session (without workspace path and
			// extension)
			String cleanFilenameLoadSession = null;
			if (workspace != null) {
				cleanFilenameLoadSession = filenameLoadSession.replace(workspace.getRemote(), "") // Remove
																									// workspace
																									// path
						.replaceFirst("\\\\", "") // Remove separator after
													// workspace path if windows
						.replaceFirst("/", ""); // Remove separator after
												// workspace path if Unix

				if (!cleanFilenameLoadSession.isEmpty() && (filenameSaveSession.equals(cleanFilenameLoadSession)
						|| filenameSaveSession.equals(cleanFilenameLoadSession.replace(FILE_SESSION_EXTENSION, ""))))
					return FormValidation
							.error("Le nom de session à sauvegarder est le même que celui de la session chargée.");
			}

			if (!filenameLoadSession.isEmpty())
				return FormValidation.warning("Une session est chargée, il est unitile de sauvegarder la session");

			if (!FilenameUtils.getExtension(filenameSaveSession).isEmpty())
				return FormValidation.warning(
						"L'extension du fichier n'est pas nécessaire. Une extensuion par défaut va être ajoutée (.session)");
			return FormValidation.ok();
		}

		/**
		 * List model to choose the alert report format
		 * 
		 * @return a {@link ListBoxModel}
		 */
		public ListBoxModel doFillChosenFormatsItems() {
			ListBoxModel items = new ListBoxModel();
			for (String format : mapFormatReport.keySet()) {
				items.add(format);
			}
			return items;
		}

		/**
		 * List model to choose authentication script
		 * 
		 * @return a {@link ListBoxModel}
		 * @throws InterruptedException
		 * @throws IOException
		 */
		public ListBoxModel doFillScriptNameItems() throws IOException, InterruptedException {

			ListBoxModel items = new ListBoxModel();
			// No workspace before the first build, so workspace is null
			if (workspace != null) {
				Collection<String> sessionsInString = workspace.act(new FileCallable<Collection<String>>() {
					private static final long serialVersionUID = 1328740269013881941L;

					public Collection<String> invoke(File f, VirtualChannel channel) throws IOException {

						// List all files with FILE_SESSION_EXTENSION on the
						// machine where the workspace is located
						Collection<File> colFiles = FileUtils.listFiles(f,
								FileFilterUtils.suffixFileFilter(FILE_SCRIPTS_EXTENSION), TrueFileFilter.INSTANCE);

						Collection<String> colString = new ArrayList<String>();

						// "Transform" File into String
						for (File file : colFiles) {
							for (String line : FileUtils.readLines(file)) {
								colString.add(line);

							}
						}
						return colString;
					}

					@Override
					public void checkRoles(RoleChecker checker) throws SecurityException {
						// Nothing to do
					}
				});

				// To not load a session, add a blank choice
				items.add("Merci de choisir un script d'authentification adapté");
				for (String s : sessionsInString) {
					items.add(s);
				}

			}

			else {

				items.add("Lancer le build au moins une fois pour créer le workspace (répertoire de travail)");

			}

			return items;

		}

		/**
		 * List model to choose the ZAP session to use. It's called on the
		 * remote machine (if present) to load all session files in the build's
		 * workspace.
		 * 
		 * @return a {@link ListBoxModel}. It can be empty if the workspace
		 *         doesn't contain any ZAP sessions.
		 * @throws InterruptedException
		 * @throws IOException
		 */
		public ListBoxModel doFillFilenameLoadSessionItems() throws IOException, InterruptedException {
			ListBoxModel items = new ListBoxModel();

			// No workspace before the first build, so workspace is null
			if (workspace != null) {
				Collection<String> sessionsInString = workspace.act(new FileCallable<Collection<String>>() {
					private static final long serialVersionUID = 1328740269013881941L;

					public Collection<String> invoke(File f, VirtualChannel channel) throws IOException {

						// List all files with FILE_SESSION_EXTENSION on the
						// machine where the workspace is located
						Collection<File> colFiles = FileUtils.listFiles(f,
								FileFilterUtils.suffixFileFilter(FILE_SESSION_EXTENSION), TrueFileFilter.INSTANCE);

						Collection<String> colString = new ArrayList<String>();

						for (File file : colFiles) {
							for (String line : FileUtils.readLines(file)) {
								if (!colString.contains(line)) {
									colString.add(line);
								}

							}
						}
						return colString;
					}

					@Override
					public void checkRoles(RoleChecker checker) throws SecurityException {
						// Nothing to do
					}
				});

				items.add(""); // To not load a session, add a blank choice

				for (String s : sessionsInString) {
					items.add(s);
				}
			}

			return items;
		}

		public FormValidation doLoadScriptsList() {
			
			
		 
			int zapProxyDefaultTimeoutInSec = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultTimeoutInSec();
			String defaultProtocol = ZAProxyBuilder.DESCRIPTOR.getDefaultProtocol();
			String zapProxyDefaultHost = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultHost();
			String zapProxyDefaultApiKey = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultApiKey();

			int zapDefaultSSHPort = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPort();
			String zapDefaultSSHUser = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHUser();
			String zapDefaultSSHPassword = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPassword();

			boolean useWebProxy = ZAProxyBuilder.DESCRIPTOR.isUseWebProxy();
		 
 

			String webProxyHost = ZAProxyBuilder.DESCRIPTOR.getWebProxyHost();
			int webProxyPort = ZAProxyBuilder.DESCRIPTOR.getWebProxyPort();
			String webProxyUser = ZAProxyBuilder.DESCRIPTOR.getWebProxyUser();
			String webProxyPassword = ZAProxyBuilder.DESCRIPTOR.getWebProxyPassword();

			String zapDefaultDirectory = ZAProxyBuilder.DESCRIPTOR.getZapDefaultDirectory();

 

			/*
			 * ======================================================= | USE WEB PROXY | =======================================================
			 */
			Proxy proxy = null;
			if (useWebProxy) {

				Authenticator.setDefault(new ProxyAuthenticator(webProxyUser, webProxyPassword));
				// cet appel permet de ne pas généraliser le passage par le
				// proxy à toutes les appels issus de la même JVM
				proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(webProxyHost, webProxyPort));
			}
			
			
			
			/*
			 * ======================================================= | CHOOSE A FREE PORT  | =======================================================
			 */
			
			
			int zapProxyPort = HttpUtilities.getPortNumber();
			
			while(HttpUtilities.portIsToken(proxy, defaultProtocol, zapProxyDefaultHost, zapProxyPort, zapProxyDefaultTimeoutInSec)){
				
				zapProxyPort = HttpUtilities.getPortNumber();
				
			}

			
			
			
			
			/*
			 * ======================================================= | start ZAP | =======================================================
			 */			
			
			final String linuxCommand = "Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh " + zapDefaultDirectory+ "zap.sh -daemon -port " + zapProxyPort;
			final String WindowsCommand = zapDefaultDirectory + "zap.bat -daemon -port "+ zapProxyPort;
 
			SSHConnexion.execCommand(zapProxyDefaultHost, zapDefaultSSHPort, zapDefaultSSHUser, zapDefaultSSHPassword,HttpUtilities.getMilliseconds(zapProxyDefaultTimeoutInSec),linuxCommand);
			/*
			 * ======================================================= |WAIT FOR SUCCESSFUL CONNEXIONd| =======================================================
			 */
		
			HttpUtilities.waitForSuccessfulConnectionToZap(proxy,defaultProtocol, zapProxyDefaultHost, zapProxyPort,zapProxyDefaultTimeoutInSec);
			
			
			
			/*
			 * ======================================================= | ZAP FILE PATH SEPARATOR | =======================================================
			 */
			try {

				ApiResponseElement set = (ApiResponseElement) CustomZapClientApi.sendRequest(defaultProtocol, zapProxyDefaultHost,
						zapProxyPort, "xml", "core", "view", "homeDirectory", null, proxy, zapProxyDefaultTimeoutInSec);
				String zapHomeDirectory = set.getValue();

				if (zapHomeDirectory.startsWith("/")) {
					setFILE_SEPARATOR("/");
				} else {
					setFILE_SEPARATOR("\\");
				}

				/* ======================================================= */

				StringBuilder sb1 = new StringBuilder();

				ApiResponseList configParamsList = null;
				configParamsList = (ApiResponseList) CustomZapClientApi.sendRequest(defaultProtocol, zapProxyDefaultHost,
						zapProxyPort, "xml", "script", "view", "listScripts", null, proxy, zapProxyDefaultTimeoutInSec);

				for (ApiResponse r : configParamsList.getItems()) {
					ApiResponseSet set1 = (ApiResponseSet) r;
					sb1.append(set1.getAttribute("name") + "\n");

				}

				String scripstList = sb1.toString();

				// probleme avec getFILE_SEPARATOR(), avant le build cette
				// fonction doit retourner une valeur
				String filePth = ROOT_PATH + getFILE_SEPARATOR() + AUTHENTICATION_SCRIPTS_PATH + getFILE_SEPARATOR()
						+ AUTHENTICATION_SCRIPTS_LIST_FILE;
				if (workspace != null) {
					File scriptsListFile = new File(workspace.getRemote(), filePth);
					FileUtils.writeByteArrayToFile(scriptsListFile, scripstList.getBytes());
				} else {
					// remplir la liste des scripts
					return FormValidation.okWithMarkup("<br><b><FONT COLOR=\"green\">Success : La liste des scripts est chargée."
									+ "<br>Scripts :<br>" + scripstList + "</FONT></b></br>");
				}

					return FormValidation.okWithMarkup("<br><b><FONT COLOR=\"green\">Success : La liste des scripts est chargée."
								+ "<br>Veuillez recharger la page afin d'accéder à cette liste</FONT></b></br>");

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
			
			finally{
				
				/*
				 * ======================================================= | Stop ZAP | =======================================================
				 */	
			 
				Map<String, String> map = null;
				map = new HashMap<String, String>();
				map.put("apikey", zapProxyDefaultApiKey);
				try {
					ApiResponseElement set = (ApiResponseElement) CustomZapClientApi.sendRequest(defaultProtocol, zapProxyDefaultHost,
							zapProxyPort, "xml", "core", "action", "shutdown", map, proxy, zapProxyDefaultTimeoutInSec);
				} catch (IOException | ParserConfigurationException | SAXException | ClientApiException e) {
					 
					e.printStackTrace();
				}
				 
			}
			
			

		}
		
		

	}

}
