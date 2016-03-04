
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


package fr.hackthem.zapkins;
 
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.FilePath.FileCallable;
import hudson.model.AbstractBuild;
import hudson.model.AbstractDescribableImpl;
import hudson.model.BuildListener;
import hudson.model.Computer;
import hudson.model.Descriptor;
import hudson.model.Hudson;
import hudson.model.Node;
import hudson.remoting.VirtualChannel;
import hudson.slaves.SlaveComputer;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import fr.hackthem.zapkins.api.CustomZapClientApi; 
import fr.hackthem.zapkins.report.ZAPreport;
import fr.hackthem.zapkins.report.ZAPreportCollection;
import fr.hackthem.zapkins.report.ZAPscannersCollection;
import fr.hackthem.zapkins.utilities.HttpUtilities;
import fr.hackthem.zapkins.utilities.ProxyAuthenticator;
import fr.hackthem.zapkins.utilities.SSHConnexion;
import fr.hackthem.zapkins.utilities.SecurityTools;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.tools.ant.BuildException;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

 

/**
 * Contains methods to start and execute ZAProxy. Members variables are bind to
 * the config.jelly placed to fr/novia/zaproxyplugin/ZAProxy
 * Cette classe permet de lancer ZAP, les noms des attributs de la classe doivent √™tre identiques √† ceux renseign√©s dans le fichier config.jelly situ√© √† fr/hackthem/zapkins/ZAProxy
 * 
 * @authors  Abdellah AZOUGARH
 *
 */
public class ZAProxy extends AbstractDescribableImpl<ZAProxy> implements Serializable {


	
	private static final long serialVersionUID = 946509532597271579L;
	private final String user = "ZAP USER";
	public static final String FILE_SESSION_EXTENSION = ".session";
	public static final String FILE_SCRIPTS_EXTENSION = ".scripts";
	public static final String AUTHENTICATION_SCRIPTS_LIST_FILE = "authenticationScriptsList.scripts";
	public static final String SESSIONS_LIST_FILE = "sessionsListFile.session";
	
	public static final String SPIDERING_RESULTS_FILE = "spidering.txt";
	public static final String AJAX_SPIDERING_RESULTS_FILE = "ajaxSpidering.txt";

	public final static String ROOT_PATH = "ZAPRProxy";
	public final String REPORTS_PATH = "reports";
	public final String SESSIONS_PATH = "sessions";
	public final String LOGS_PATH = "logs";
	public final static String AUTHENTICATION_SCRIPTS_PATH = "scripts";
	
	private static final String ZAP_PROG_NAME_BAT = "zap.bat";
	private static final String ZAP_PROG_NAME_SH = "zap.sh";
	public static final String CMD_LINE_PORT = "-port";
	public static final String CMD_LINE_DAEMON = "-daemon";
	
	

	public static String FILE_SEPARATOR = "";
	
	
	
	private final String httpHostname;
	private final String httpRealm ;
	private final String httpLoggedInIndicator ;
	private final String httpLoggedOutIndicator;
	private final String httpUsername ;
	private final String httpPassword ;
	private final int httpAuthenticationPort;

 
	/** the scan mode (AUTHENTICATED/NOT_AUTHENTICATED) */
	private final String scanMode;

	/** the authentication mode (SCRIPT_BASED/FORM_BASED) */
	private final String authenticationMode;


	/** URL to attack by ZAProxy */
	private final String targetURL;

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
	private String reportName;
	
	/** Filename for ZAProxy reports. It can contain a relative path (it's derived from the one above) */
	private  String evaluatedFilenameReports;
	

	/**
	 * The file policy to use for the scan. It contains only the policy name
	 * (without extension)
	 */
	private final String chosenPolicy;

	/** Id of the newly created context */
	private String contextId;
	
	/** Id of the newly created user */
	private String userId;
	
	/** Id of the newly created scan */
	private String scanId;
	
	
	//ce champ n'a pas besoin d'Ítre sÈrialisÈ, faire attention ‡ ce point si on souhaite garder la configuration du plugin peristente
	private transient CustomZapClientApi zapClientAPI;


		@DataBoundConstructor
		public ZAProxy( String httpHostname, String httpRealm , String httpLoggedInIndicator ,String httpLoggedOutIndicator,String httpUsername ,String httpPassword,int httpAuthenticationPort,
				ArrayList<String> chosenScanners, String scanMode,
				String authenticationMode,   
				String targetURL, boolean spiderURL, boolean ajaxSpiderURL, boolean scanURL,  
				String scriptName, String loginUrl, String contextName, String includedUrl, String excludedUrl,
				String formLoggedInIndicator, String formLoggedOutIndicator, String scriptLoggedInIndicator,
				String scriptLoggedOutIndicator, String postData, String usernameParameter, String passwordParameter,
				String formUsername, String formPassword, String scriptUsername, String scriptPassword,
				 boolean scanURLAsUser, boolean saveReports, ArrayList<String> chosenFormats,
				String reportName,    String chosenPolicy,
				String contextId, String userId, String scanId) {
			
			
			super();	
			this.httpHostname=httpHostname;
			this.httpRealm=httpRealm;
			this.httpLoggedInIndicator=httpLoggedInIndicator;
			this.httpLoggedOutIndicator=httpLoggedOutIndicator;
			this.httpUsername=httpUsername;
			this.httpPassword=httpPassword;
			this.httpAuthenticationPort=httpAuthenticationPort;
	
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
			this.reportName = reportName;
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
		s += "httpHostname [" + httpHostname + "]\n";
		s += "httpRealm [" + httpRealm + "]\n";
		s += "httpLoggedInIndicator [" + httpLoggedInIndicator + "]\n";
		s += "httpLoggedOutIndicator [" + httpLoggedOutIndicator + "]\n";
		s += "httpUsername [" + httpUsername + "]\n";
		s += "httpAuthenticationPort [" + httpAuthenticationPort + "]\n";		
		s += "--------------------------------------------------";
		s += "saveReports [" + saveReports + "]\n";
		s += "chosenFormats [" + chosenFormats + "]\n";
		s += "reportName [" + evaluatedFilenameReports + "]\n";
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
		s += "scriptUsername [" + scriptUsername + "]\n";
		s += "formUsername [" + formUsername + "]\n";
		s += "--------------------------------------------------";

		return s;
	}


	public String getHttpHostname() {
		return httpHostname;
	}

	public String getHttpRealm() {
		return httpRealm;
	}

	public String getHttpLoggedInIndicator() {
		return httpLoggedInIndicator;
	}

	public String getHttpLoggedOutIndicator() {
		return httpLoggedOutIndicator;
	}

	public String getHttpUsername() {
		return httpUsername;
	}

	public String getHttpPassword() {
		return httpPassword;
	}
	
	public int getHttpAuthenticationPort(){
		return httpAuthenticationPort;
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

	public String getReportName() {
		return reportName;
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
	
	//get and set of the new field which will contain the evaluated value of the report file name. So the environment variable will persist after each build

	   public String getEvaluatedFilenameReports() {
				return evaluatedFilenameReports;
			}
		
		public void setEvaluatedFilenameReports(String evaluatedFilenameReports) {
				this.evaluatedFilenameReports = evaluatedFilenameReports;
			}
			
	/**
	 * Return the ZAProxy program name with separator prefix (\zap.bat or /zap.sh) depending of the build node and the OS.
	 * 
	 * @param build
	 * @return the ZAProxy program name with separator prefix (\zap.bat or /zap.sh)
	 * @throws IOException
	 * @throws InterruptedException
	 */
	private String getZAPProgramNameWithSeparator(AbstractBuild<?, ?> build) throws IOException, InterruptedException {
		Node node = build.getBuiltOn();
		String zapProgramName = "";
		
		// Append zap program following Master/Slave and Windows/Unix
		if( "".equals(node.getNodeName())) { // Master
			if( File.pathSeparatorChar == ':' ) { // UNIX
				zapProgramName = "/" + ZAP_PROG_NAME_SH;
			} else { // Windows (pathSeparatorChar == ';')
				zapProgramName = "\\" + ZAP_PROG_NAME_BAT;
			}
		} 
		else { // Slave
			if( "Unix".equals(((SlaveComputer)node.toComputer()).getOSDescription()) ) {
				zapProgramName = "/" + ZAP_PROG_NAME_SH;
			} else {
				zapProgramName = "\\" + ZAP_PROG_NAME_BAT;
			}
		}
		return zapProgramName;
	}
	
/**
 * Start ZAProxy using command line. It uses host and port configured in Jenkins admin mode and
 * ZAProxy program is launched in daemon mode (i.e without UI).
 * ZAProxy is started on the build's machine (so master machine ou slave machine) thanks to 
 * {@link FilePath} object and {@link Launcher} object.
 * 
 * @param zapProgram the full path to ZAP proxy installation directory
 * @param zapProxyPort the port number which is randomly choosen for this instance
 * @param build
 * @param listener the listener to display log during the job execution in jenkins
 * @param launcher the object to launch a process locally or remotely
 * @throws InterruptedException 
 * @throws IOException 
 * @throws IllegalArgumentException 
 */
public void startZAPLocally(String zapProgram, int zapProxyPort,  AbstractBuild<?, ?> build, BuildListener listener, Launcher launcher) 
		throws IllegalArgumentException, IOException, InterruptedException {
	 
	
	FilePath ws = build.getWorkspace();
	if (ws == null) {
		Node node = build.getBuiltOn();
		if (node == null) {
			throw new NullPointerException("no such build node: " + build.getBuiltOnStr());
		}
		throw new NullPointerException("no workspace from node " + node + " which is computer " + node.toComputer() + " and has channel " + node.getChannel());
	}
	
	// Contains the absolute path to ZAP program
	FilePath zapPathWithProgName = new FilePath(ws.getChannel(), zapProgram + getZAPProgramNameWithSeparator(build));
	listener.getLogger().println("Start ZAProxy [" + zapPathWithProgName.getRemote() + "]");
	
	// Command to start ZAProxy with parameters
	List<String> cmd = new ArrayList<String>();
	cmd.add(zapPathWithProgName.getRemote());
	cmd.add(CMD_LINE_DAEMON);
	cmd.add(CMD_LINE_PORT);
	cmd.add(String.valueOf(zapProxyPort));

		
	EnvVars envVars = build.getEnvironment(listener);
	// on Windows environment variables are converted to all upper case,
	// but no such conversions are done on Unix, so to make this cross-platform,
	// convert variables to all upper cases.
	for(Map.Entry<String,String> e : build.getBuildVariables().entrySet())
		envVars.put(e.getKey(),e.getValue());
	
	FilePath workDir = new FilePath(ws.getChannel(), zapProgram);

	
	// Launch ZAP process on remote machine (on master if no remote machine)
	launcher.launch().cmds(cmd).envs(envVars).stdout(listener).pwd(workDir).start();

}	


public CustomZapClientApi executeZAP(AbstractBuild build, Launcher launcher, BuildListener listener)   {
	
	
	FilePath workspace=build.getWorkspace();
	
	
	//permit to update the values of parameters when the admin makes changes 	
	//#######################################################################################################
	
	String zapProxyDirectory=ZAProxyWrapper.DESCRIPTOR.getZapDefaultDirectory();
	
	boolean startZAPFirst = ZAProxyWrapper.DESCRIPTOR.isStartZAPFirst();
	String zapInstallationType = ZAProxyWrapper.DESCRIPTOR.getZapInstallationType();
	String protocol=ZAProxyWrapper.DESCRIPTOR.getDefaultProtocol();
	String zapProxyHost = ZAProxyWrapper.DESCRIPTOR.getZapProxyDefaultHost();	
	int zapProxyPort;
	String zapProxyKey = ZAProxyWrapper.DESCRIPTOR.getZapProxyDefaultApiKey();
	int zapProxyDefaultTimeoutInSec = ZAProxyWrapper.DESCRIPTOR.getZapProxyDefaultTimeoutInSec();
	
	boolean stopZAPAtEnd = ZAProxyWrapper.DESCRIPTOR.isStopZAPAtEnd();	
	boolean useWebProxy = ZAProxyWrapper.DESCRIPTOR.isUseWebProxy();
	String webProxyHost = ZAProxyWrapper.DESCRIPTOR.getWebProxyHost();
	int webProxyPort = ZAProxyWrapper.DESCRIPTOR.getWebProxyPort();
	String webProxyUser = ZAProxyWrapper.DESCRIPTOR.getWebProxyUser();
	String webProxyPassword = ZAProxyWrapper.DESCRIPTOR.getWebProxyPassword();
	
	int zapDefaultSSHPort = ZAProxyWrapper.DESCRIPTOR.getZapDefaultSSHPort();
	int zapProxyDefaultTimeoutSSHInSec = ZAProxyWrapper.DESCRIPTOR.getZapProxyDefaultTimeoutSSHInSec();	
	String zapDefaultSSHUser = ZAProxyWrapper.DESCRIPTOR.getZapDefaultSSHUser();
	String zapDefaultSSHPassword = ZAProxyWrapper.DESCRIPTOR.getZapDefaultSSHPassword();		
	
	boolean debugMod = ZAProxyWrapper.DESCRIPTOR.isDebugMod();
	int debugPort=ZAProxyWrapper.DESCRIPTOR.getDebugPort();
	
	String authorizedURL=ZAProxyWrapper.DESCRIPTOR.getAuthorizedURLs();
	//#######################################################################################################

	listener.getLogger().println("DebugMod : "+debugMod);
	
	/*
	 * ======================================================= | REPLACE ENVIRONEMENT VARIABLES | =======================================================
	 */
	listener.getLogger().println("------- START Replace environment variables -------");
	
	String reportName=getReportName();
	try {
		reportName=applyMacro( build,  listener,  reportName);
	} catch (InterruptedException e1) {
		 
		listener.error(ExceptionUtils.getStackTrace(e1));
	}


	//we don't overwrite the file name containing the environment variables
	//the evaluated value is saved in an other file name 
	setEvaluatedFilenameReports(reportName);
	
	
	listener.getLogger().println("ReportName : "+reportName);
	
	listener.getLogger().println("------- END Replace environment variables -------");
			
	/*
	 * ===================================================================================================================================================
	 */		
		
	

	/*
	 * ======================================================= | USE WEB PROXY | =======================================================
	 */
	if (useWebProxy) {
		// Ici on gÈnÈralise l'utilisation du proxy web ‡ tous les appels
		// passÈs via la JVM
		listener.getLogger().println("Using web proxy");
		System.out.println("Using web proxy");
		CustomZapClientApi.setWebProxyDetails(webProxyHost, webProxyPort, webProxyUser, webProxyPassword);
	} else {
		listener.getLogger().println("Skip using web proxy");
		System.out.println("Skip using web proxy");
	}	
	
	/*
	 * ===================================================================================================================================		
		
		
		/*
		 * =================================================== | CHOOSE A FREE PORT  | =======================================================
		 */
		
		listener.getLogger().println("------- PORT NUMBER CHOOSER -------");
		System.out.println("------- PORT NUMBER CHOOSER -------");
		zapProxyPort = HttpUtilities.getPortNumber();
		
		while(HttpUtilities.portIsToken(null, protocol, zapProxyHost, zapProxyPort, zapProxyDefaultTimeoutInSec, listener)){
			
			zapProxyPort = HttpUtilities.getPortNumber();
			
		}
		
		listener.getLogger().println("PORT : "+zapProxyPort);
		System.out.println("PORT : "+zapProxyPort);
		
		
		/*************** MOD DEBUG ***************************/
		
		if(debugMod == true){
		zapProxyPort=debugPort;
		listener.getLogger().println("PORT (DEBUG): "+zapProxyPort);
		System.out.println("PORT (DEBUG): "+zapProxyPort);
		}
		
		/*********************************************************************************************/
		
		listener.getLogger().println("Perform ZAProxy");
		System.out.println("Perform ZAProxy");
		
		final String sshLinuxCommand = "Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh " + zapProxyDirectory+ "zap.sh -daemon -port " + zapProxyPort;
		//final String windowsCommand = zapDefaultDirectory+"zapDefaultDirectoryzap.bat -daemon -port " + zapProxyPort;		
		
		/*
		 * ======================================================= | start ZAP | =======================================================
		 */
		if (startZAPFirst) {
			
		listener.getLogger().println("Starting ZAP");
		System.out.println("Starting ZAP");
		switch(zapInstallationType){
		
			case "LOCALE":
				listener.getLogger().println("Starting ZAP locally");	
				System.out.println("Starting ZAP locally");
					try {
						startZAPLocally(zapProxyDirectory, zapProxyPort, build, listener, launcher);
					} catch (IllegalArgumentException | IOException | InterruptedException e) {
						
						listener.error(ExceptionUtils.getStackTrace(e));
					}
				break;
				
				
			case "DISTANTE" :
				listener.getLogger().println("Starting ZAP remotely (SSH)");	
				System.out.println("Starting ZAP remotely (SSH)");
				//MOD DEBUG (uncomment this line to de-activate the debug mod
				SSHConnexion.execCommand(zapProxyHost, zapDefaultSSHPort, zapDefaultSSHUser, zapDefaultSSHPassword,HttpUtilities.getMilliseconds(zapProxyDefaultTimeoutSSHInSec ),sshLinuxCommand, listener);
	 
				break ;
				
			default :
				System.out.println("Unsupported installation location");
				break ;			
			
		}		
	}

	else {
		listener.getLogger().println("Skip starting ZAP");
		listener.getLogger().println("startZAPFirst : " + startZAPFirst);
	}
	
	/*
	 * ======================================================= |WAIT FOR SUCCESSFUL CONNEXIONd| =======================================================
	 */
	
	//ici le proxy est Ègal ‡ null car on applique une configuration gÈnÈrale o˘ tout appel rÈseau provennat de la VM passe par le proxy 
	HttpUtilities.waitForSuccessfulConnectionToZap(null,protocol, zapProxyHost, zapProxyPort,zapProxyDefaultTimeoutInSec, listener);
	
	listener.getLogger().println("targetURL : " + targetURL);
	listener.getLogger().println("authorizedURL : \n" + authorizedURL);
	
	if(!SecurityTools.isUrlAuditable(targetURL, authorizedURL)){
		
		throw new BuildException("The chosen URL is not allowed, please contact the security team to justify your choice");
	}	
	 
	zapClientAPI = new CustomZapClientApi(protocol,zapProxyHost, zapProxyPort, zapProxyKey, listener,debugMod);	 	

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

				saveReport(ROOT_PATH + getFILE_SEPARATOR() + REPORTS_PATH, evaluatedFilenameReports, format, listener,
						workspace, zapClientAPI);
			}
		}



		// }
	} catch (Exception e) {
		listener.error(ExceptionUtils.getStackTrace(e));
		//buildSuccess = false;
	} finally {

		if (stopZAPAtEnd) {				

			try {
				stopZAP(zapClientAPI, listener);
			} catch (ClientApiException e) {
				listener.error(ExceptionUtils.getStackTrace(e));
			}
		}

		//buildSuccess = true;

	}
	
	return zapClientAPI;
}

/**
 * Replace macro with environment variable if it exists
 * @param build
 * @param listener
 * @param macro
 * @return
 * @throws InterruptedException
 */
private  String applyMacro(AbstractBuild build, BuildListener listener, String macro)
        throws InterruptedException{
    try {
        EnvVars envVars = new EnvVars(Computer.currentComputer().getEnvironment());
        envVars.putAll(build.getEnvironment(listener));
        envVars.putAll(build.getBuildVariables());
        return Util.replaceMacro(macro, envVars);
    } catch (IOException e) {
        listener.getLogger().println("Failed to apply macro " + macro);
        listener.error(ExceptionUtils.getStackTrace(e));
        
    }
    return macro;
}
	private void executeZAPSessionNotLoaded(FilePath workspace, BuildListener listener) throws IOException { 
		
		boolean spiderURL = ZAProxyWrapper.DESCRIPTOR.isSpiderURL();
		boolean ajaxSpiderURL = ZAProxyWrapper.DESCRIPTOR.isAjaxSpiderURL();
		boolean scanURL = ZAProxyWrapper.DESCRIPTOR.isScanURL();		
		boolean debugMod = ZAProxyWrapper.DESCRIPTOR.isDebugMod();
		String zapHomeDirectory = ZAProxyWrapper.DESCRIPTOR.getZapDefaultDirectory();
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
				zapClientAPI.logSpiderResults( scanId, workspace, zapHomeDirectory,  ROOT_PATH,   LOGS_PATH,   SPIDERING_RESULTS_FILE);
				
				if(debugMod==true)
				zapClientAPI.viewSpiderResults(scanId, listener);
				
				
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
				zapClientAPI.logAjaxSpiderResults(workspace,zapHomeDirectory,ROOT_PATH,LOGS_PATH, AJAX_SPIDERING_RESULTS_FILE );
				
				if(debugMod==true)
				zapClientAPI.viewAjaxSpiderResults(listener);
			} else {
				listener.getLogger().println("Skip Ajax spidering the site [" + targetURL + "]");
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
			
			case "HTTP_BASED": {
				listener.getLogger().println("AUTHENTICATION_MOD :  : HTTP_BASED");
				setUpHttpBasedAuthenticationConf(zapClientAPI, listener);
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
				zapClientAPI.logSpiderResults( scanId, workspace, zapHomeDirectory,  ROOT_PATH,   LOGS_PATH,   SPIDERING_RESULTS_FILE);
				
				if(debugMod==true)
				zapClientAPI.viewSpiderResults(scanId, listener);

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
				zapClientAPI.logAjaxSpiderResults(workspace,zapHomeDirectory,ROOT_PATH,LOGS_PATH, AJAX_SPIDERING_RESULTS_FILE );
				
				if(debugMod==true)
				zapClientAPI.viewAjaxSpiderResults(listener);
			} else {
				listener.getLogger()
						.println("Skip Ajax spidering the site [" + targetURL + "] As User [" + userId + "]");
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
		if(scanMode  == null )
			return "" ;
		else 
		return this.scanMode.equalsIgnoreCase(testTypeName) ? "true" : "";
	}

	public String isAuthenticationMode(String testTypeName) {
		if(authenticationMode  == null )
			return "" ;
		else 
		return this.authenticationMode.equalsIgnoreCase(testTypeName) ? "true" : "";
	}

	/**
	 * @param reportName the reportName to set
	 */
	public void setReportName(String reportName) {
		this.reportName = reportName;
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
	private void saveReport(String pathReports, String reportName, String format, BuildListener listener,
			FilePath workspace, CustomZapClientApi clientApi) throws IOException, ClientApiException {

		final String fullFileName = pathReports + getFILE_SEPARATOR() + format + getFILE_SEPARATOR() + reportName
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
		// Ici on met le tous √† OFF sinon les scanners seront activ√©s malg√©
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
			// ETAPE 1 : on d√©sactive tous les scanners
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
		// r√©cup√®re l'id du contexte si celui l√† est cr√©e sinon elle le cr√©e et
		// retourne son id
		String contextId = zapClientAPI.getContextId(contextName, listener);
		setContextId(contextId);
		listener.getLogger().println("ContextId : " + contextId);

		
		zapClientAPI.includeInContext(includedUrl, contextName, listener);
		
		if (!excludedUrl.equals("")) {
			zapClientAPI.excludeFromContext(excludedUrl, contextName, listener);
			//voir ‡ quel moment il faut appeler les deux action ci-dessous :
			zapClientAPI.excludeFromSpider(excludedUrl, listener);
			zapClientAPI.excludeFromActifScan(excludedUrl, listener);
			
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
		
		
		if (!scriptLoggedInIndicator.equals("")) {
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedInIndicator(contextId, scriptLoggedInIndicator, listener);
		}
		
		if (!scriptLoggedOutIndicator.equals("")) {
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedOutIndicator(contextId, scriptLoggedOutIndicator, listener);
		}
		
		
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.listUserConfigInformation(contextId, listener);

		listener.getLogger().println("---------------------------------------");
		String userid = zapClientAPI.setUserScriptAuthConfig(contextId, user, scriptUsername, scriptPassword, listener);
		this.setUserId(userid);

		zapClientAPI.enableUser(contextId, userid, listener);

		/*********************** Forced User **********************************/
		// https://groups.google.com/forum/#!topic/zaproxy-users/GRtzMJ4WJzk
		// pour que la partie ajaxSpider se fasse d'une mani√®re authentifi√©e il
		// faut activer et renseigner le ForcedUser
		zapClientAPI.isForcedUserModeEnabled(listener);
		zapClientAPI.setForcedUser(contextId, userid, listener);
		zapClientAPI.getForcedUser(contextId, listener);
		zapClientAPI.setForcedUserModeEnabled(true, listener);
		zapClientAPI.isForcedUserModeEnabled(listener);

		/*********************************************************************/

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
	private void setUpHttpBasedAuthenticationConf(CustomZapClientApi zapClientAPI, BuildListener listener) {

		/***************** AUTHENTIFICATION ********************/
		listener.getLogger().println("---------------------------------------");

		zapClientAPI.setHttpBasedAuthentication(contextId, httpHostname,httpRealm, httpAuthenticationPort, listener);
		
		
		if (!httpLoggedInIndicator.equals("")) {
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedInIndicator(contextId, httpLoggedInIndicator, listener);
		}
		
		if (!httpLoggedOutIndicator.equals("")) {
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedOutIndicator(contextId, httpLoggedOutIndicator, listener);
		}
		
		
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.listUserConfigInformation(contextId, listener);

		listener.getLogger().println("---------------------------------------");
		
		String userid =zapClientAPI.setUpUser(listener, httpUsername, httpPassword,  contextId);
		
		this.setUserId(userid);
		/*********************************************************************/

	}


	private void setUpFormBasedAuthenticationConf(CustomZapClientApi zapClientAPI, BuildListener listener) {

		/***************** AUTHENTIFICATION ********************/
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setUpFormBasedAuthentication(contextId, loginUrl, postData, usernameParameter, passwordParameter,
				listener);
		
		
		if (!formLoggedInIndicator.equals("")) {
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedInIndicator(contextId, formLoggedInIndicator, listener);
		}
		
		if (!formLoggedOutIndicator.equals("")) {
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedOutIndicator(contextId, formLoggedOutIndicator, listener);
		}

		listener.getLogger().println("---------------------------------------");
		zapClientAPI.listUserConfigInformation(contextId, listener);

		listener.getLogger().println("---------------------------------------");
		String userid = zapClientAPI.setUserFormAuthConfig(contextId, user, formUsername, formPassword, listener);
		this.setUserId(userid);

		zapClientAPI.enableUser(contextId, userid, listener);

		/*********************** Forced User **********************************/
		// https://groups.google.com/forum/#!topic/zaproxy-users/GRtzMJ4WJzk
		// pour que la partie ajaxSpider se fasse d'une mani√®re authentifi√©e il
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
	public void stopZAP(CustomZapClientApi zapClientAPI, BuildListener listener) throws ClientApiException {
		String zapProxyKey = ZAProxyWrapper.DESCRIPTOR.getZapProxyDefaultApiKey();
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
	 * See <tt>src/main/resources/fr/hackthem/zaproxyplugin/ZAProxy/*.jelly</tt>
	 * for the actual HTML fragment for the configuration screen.
	 */
	@Extension
	public static class ZAProxyDescriptorImpl extends Descriptor<ZAProxy> implements Serializable {

		private static final long serialVersionUID = 4028279269334325901L;

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
			// On supprime l'√©l√©ment "ALL SCANNERS" et on le remet au d√©but.
			ArrayList<String> tab = new ArrayList<String>(mapScannersTypes.keySet());
			tab.remove(tab.indexOf("ALL SCANNERS"));
			tab.add(0, "ALL SCANNERS");
			return tab;
		}

		public void setWorkspace(FilePath ws) {
			this.workspace = ws;
		}	
		
		
		public FormValidation doCheckTargetURL(@QueryParameter("targetURL") final String targetURL) {
			
			
			String  authorizedURL=ZAProxyWrapper.DESCRIPTOR.getAuthorizedURLs();
			
			if(!SecurityTools.isUrlAuditable(targetURL, authorizedURL)){
				
				return FormValidation.error("URL hors scope (non authoris√©e)");
			}
			
			return FormValidation.ok();
			
		
		}

		/**
		 * Performs on-the-fly validation of the form field 'reportName'.
		 *
		 * @param reportName
		 *            This parameter receives the value that the user has typed.
		 * @return Indicates the outcome of the validation. This is sent to the
		 *         browser.
		 *         <p>
		 *         Note that returning {@link FormValidation#error(String)} does
		 *         not prevent the form from being saved. It just means that a
		 *         message will be displayed to the user.
		 */
		public FormValidation doCheckReportName(@QueryParameter("reportName") final String reportName) {
			if (reportName.isEmpty())
				return FormValidation.error("Ce champ est obligatoire");
			if (!FilenameUtils.getExtension(reportName).isEmpty())
				return FormValidation.warning("L'extension du fichier n'est pas n√©cessaire !");
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
							.error("The saved session name is the same as the name of the loaded one");
			}

			if (!filenameLoadSession.isEmpty())
				return FormValidation.warning("A session is already loaded, there is no need to save the session");

			if (!FilenameUtils.getExtension(filenameSaveSession).isEmpty())
				return FormValidation.warning(
						"The file extension is not needed. Adefault one will be added (.session)");
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
				items.add("Please choose one of the authentication scripts");
				for (String s : sessionsInString) {
					items.add(s);
				}

			}

			else {

				items.add("First, launch the job once in order to create the workspace");

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
			
			 
			final int zapProxyDefaultTimeoutInSec = ZAProxyWrapper.DESCRIPTOR.getZapProxyDefaultTimeoutInSec();
			
			final String defaultProtocol = ZAProxyWrapper.DESCRIPTOR.getDefaultProtocol();
			final String zapProxyDefaultHost = ZAProxyWrapper.DESCRIPTOR.getZapProxyDefaultHost();
			final String zapProxyDefaultApiKey = ZAProxyWrapper.DESCRIPTOR.getZapProxyDefaultApiKey();
			final String zapDefaultDirectory = ZAProxyWrapper.DESCRIPTOR.getZapDefaultDirectory();

			final int zapDefaultSSHPort = ZAProxyWrapper.DESCRIPTOR.getZapDefaultSSHPort();
			final String zapDefaultSSHUser = ZAProxyWrapper.DESCRIPTOR.getZapDefaultSSHUser();
			final String zapDefaultSSHPassword = ZAProxyWrapper.DESCRIPTOR.getZapDefaultSSHPassword();

			final boolean useWebProxy = ZAProxyWrapper.DESCRIPTOR.isUseWebProxy();
			final String webProxyHost = ZAProxyWrapper.DESCRIPTOR.getWebProxyHost();
			final int webProxyPort = ZAProxyWrapper.DESCRIPTOR.getWebProxyPort();
			final String webProxyUser = ZAProxyWrapper.DESCRIPTOR.getWebProxyUser();
			final String webProxyPassword = ZAProxyWrapper.DESCRIPTOR.getWebProxyPassword();

			final String zapInstallationType = ZAProxyWrapper.DESCRIPTOR.getZapInstallationType();
			
			final boolean  debugMod = ZAProxyWrapper.DESCRIPTOR.isDebugMod();			
			final int debugPort = ZAProxyWrapper.DESCRIPTOR.getDebugPort();
            
 

			/*
			 * ======================================================= | USE WEB PROXY | =======================================================
			 */
			Proxy proxy = null;
			if (useWebProxy) {
				System.out.println("Using Web Proxy");
				Authenticator.setDefault(new ProxyAuthenticator(webProxyUser, webProxyPassword));
				// cet appel permet de ne pas g√©n√©raliser le passage par le
				// proxy √† toutes les appels issus de la m√™me JVM
				proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(webProxyHost, webProxyPort));
			}
			else {
				System.out.println("Skip Using Web Proxy");
			}			
			
			/*
			 * ======================================================= | CHOOSE A FREE PORT  | =======================================================
			 */			
			
			int zapProxyPort = HttpUtilities.getPortNumber();
			
			while(HttpUtilities.portIsToken(proxy, defaultProtocol, zapProxyDefaultHost, zapProxyPort, zapProxyDefaultTimeoutInSec)){
				
				zapProxyPort = HttpUtilities.getPortNumber();				
			}	
						
			/*************** MOD DEBUG ***************************/
			
			if(debugMod){
			zapProxyPort=debugPort;			 
			System.out.println("PORT (DEBUG): "+zapProxyPort);
			}
			
			/*********************************************************************************************/
			
			/*
			 * ======================================================= | start ZAP | =======================================================
			 */			
			
			final String sshLinuxCommand = "Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh " + zapDefaultDirectory+ "zap.sh -daemon -port " + zapProxyPort;
			//final String WindowsCommand = zapDefaultDirectory + "zap.bat -daemon -port "+ zapProxyPort;
			
			
			switch(zapInstallationType){
			
		 
			case "LOCALE" :				 	
				System.out.println("Starting ZAP locally");
				final int port = zapProxyPort;
				Thread t1 = new Thread(new Runnable() {
				    public void run()
				    {
				    	try {							
							 
							startZAPLocally(zapDefaultDirectory, port) ;
						 
						} catch (IOException e1) {
							 
							e1.printStackTrace();
						} catch (InterruptedException e1) {
							 
							e1.printStackTrace();
							 
						}
		 
				    }});  
				    t1.start();	 
				
				break ;
				
			case "DISTANTE" :
				System.out.println("Starting ZAP remotely (SSH)");	
				//MOD DEBUG (uncomment this line to de-activate the debug mod
				SSHConnexion.execCommandSshPasswordAuth(zapProxyDefaultHost, zapDefaultSSHPort, zapDefaultSSHUser, zapDefaultSSHPassword,HttpUtilities.getMilliseconds(zapProxyDefaultTimeoutInSec),sshLinuxCommand);
				//TODO
				//SSHConnexion.execCommandSshKeydAuth(...
				
				System.out.println("connexion SSH : END");
				
			default :
				break;
			}					
 
			/*
			 * ======================================================= |WAITING ZAP STARTING| =======================================================
			 */
		
			HttpUtilities.waitForSuccessfulConnectionToZap(proxy,defaultProtocol, zapProxyDefaultHost, zapProxyPort,zapProxyDefaultTimeoutInSec);
			
					
			/*
			 * ======================================================= | LOAD AUTHENTICATION SCRIPTS LIST | =======================================================
			 */
			
			return CustomZapClientApi.loadAuthenticationScriptsList( defaultProtocol,  zapProxyDefaultHost,  zapProxyPort,  zapProxyDefaultApiKey, proxy, zapProxyDefaultTimeoutInSec
					,  ROOT_PATH,  AUTHENTICATION_SCRIPTS_PATH,  AUTHENTICATION_SCRIPTS_LIST_FILE, workspace );
		}
		

		/**
		 * @param zapProxyDirectory ZAP Proxy Directory 
		 * @param zapProxyPort ZAP Proxy Port number
		 * @throws IOException 
		 * @throws InterruptedException 
		 */
		
		private void startZAPLocally(String zapProxyDirectory , int zapProxyPort) throws IOException, InterruptedException{			 
		   
			File pathToExecutable;
			if (Hudson.isWindows()){ //TODO : find an other way to do that 
			
			pathToExecutable = new File( zapProxyDirectory+"\\",ZAP_PROG_NAME_BAT );
			}
			else {
				
			pathToExecutable = new File( zapProxyDirectory+"/",ZAP_PROG_NAME_SH );	
			}
			// Command to start ZAProxy with parameters
			List<String> cmd = new ArrayList<String>();
			cmd.add(pathToExecutable.getAbsolutePath());
			cmd.add(CMD_LINE_DAEMON);
			cmd.add(CMD_LINE_PORT);
			cmd.add(String.valueOf(zapProxyPort));
			
			System.out.println("cmd : "+cmd.toString());
			
			ProcessBuilder builder = new ProcessBuilder(cmd);
			builder.directory( new File(zapProxyDirectory )); // this is where you set the root folder for the executable to run with
			builder.redirectErrorStream(true);
			Process process =  builder.start();

			Scanner s = new Scanner(process.getInputStream());
			StringBuilder text = new StringBuilder();
			while (s.hasNextLine()) {
			  text.append(s.nextLine());
			  text.append("\n");
			}
			s.close();

			int result = process.waitFor();

			System.out.printf( "Process exited with result %d and output %s%n", result, text );
			

		} 
		
	}


}
