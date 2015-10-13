

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

package fr.novia.zaproxyplugin;

 
import fr.novia.zaproxyplugin.report.ZAPreport;
import fr.novia.zaproxyplugin.report.ZAPreportCollection;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.FilePath.FileCallable;
import hudson.Launcher;
import hudson.model.AbstractDescribableImpl;
import hudson.model.BuildListener;
import hudson.model.EnvironmentSpecific;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.Computer;
import hudson.model.Descriptor;
import hudson.model.JDK;
import hudson.model.Node;
import hudson.remoting.VirtualChannel;
import hudson.slaves.NodeSpecific;
import hudson.slaves.SlaveComputer;
import hudson.tools.ToolDescriptor;
import hudson.tools.ToolInstallation;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;

import java.io.BufferedReader;
import java.io.File;
import java.io.FilenameFilter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import jenkins.model.Jenkins;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.io.filefilter.FileFilterUtils;
import org.apache.commons.io.filefilter.TrueFileFilter;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.tools.ant.BuildException;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApi;
import org.zaproxy.clientapi.core.ClientApiException;

/**
 * Contains methods to start and execute ZAProxy.
 * Members variables are bind to the config.jelly placed to fr/novia/zaproxyplugin/ZAProxy
 * 
 * @author ludovic.roucoux
 *
 */
public class ZAProxy extends AbstractDescribableImpl<ZAProxy> implements Serializable  {

	private static final long serialVersionUID = 3381268691497579059L;	
	private static final String user = "ZAPR USER"; 
	public static final String FILE_SESSION_EXTENSION = ".session";	
	public static final String FILE_SCRIPTS_EXTENSION = ".scripts";	
	public static final String authenticationScriptsListFile="authenticationScriptsList.scripts";
	public static final String sessionsListFile="sessionsListFile.session";
	
	public  String FILE_SEPARATOR="" ;





	/** the scan mode (AUTHENTICATED/NOT_AUTHENTICATED) */
	private String scanMode;	
	
	/* Charger la liste des scripts d'authentification */
	private boolean loadAuthenticationsScripts;
	
	/** the authentication mode (SCRIPT_BASED/FORM_BASED) */
	private String authenticationMode;
	
	/** Host configured when ZAProxy is used as proxy */
	private String zapProxyHost;	
	/** Port configured when ZAProxy is used as proxy */
	private int zapProxyPort;		
	/** the secret API key when ZAProxy is used */
	private String zapProxyKey ;

	private String zapProxyDirectory;
	
	
	/** Use a web Proxy or not by ZAProxy */
	private boolean useWebProxy;
	 
	
	/** proxyWeb */
	private String webProxyHost;
	/** proxyWeb */
	private  int webProxyPort;
	/** proxyWeb */
	private  String webProxyUser;
	/** proxyWeb */
	private String webProxyPassword;	
	
	
	/** Use SSH connection **/

	/** SSH PORT  configured when ZAProxy is used as proxy */
	private int zapSSHPort;
	

	/** SSH USER configured when ZAProxy is used as proxy */
	private String  zapSSHUser;
	
	
	/** SSH PASSWORD configured when ZAProxy is used as proxy */
	private String  zapSSHPassword;
	
	
	
	
	

	
	
	/** Filename to load ZAProxy session. Contains the absolute path to the session */
	private final String filenameLoadSession;
	
	/** URL to attack by ZAProxy */
	private final String targetURL;
	
	/** Realize a url spider or not by ZAProxy */
	private boolean spiderURL;

	/** Realize a url AjaxSpider or not by ZAProxy */
	private final boolean ajaxSpiderURL;
	
	/** Realize a url scan or not by ZAProxy */
	private final boolean scanURL;
	
	/** Realize a url spider as user or not by ZAProxy */
	private final boolean spiderAsUser;	
	
	/** Authentication script name*/	
	private final String scriptName;	

	/** loggin url**/
	private final String loginUrl;
	
	/** context Name**/
	private final String contextName;	
	
	

	/** Included url in scan **/
	private final String includedUrl;
	
	/** Exclude url from scan **/
	private final String excludedUrl;
	
	

	/** FORM : logged in indication*/
	private final String formLoggedInIndicator;
	
	/** FORM : logged out indicator */	
	private final String formLoggedOutIndicator;
	
	/** SCRIPT : logged in indication*/
	private final String scriptLoggedInIndicator;
	
	/** SCRIPT : logged out indicator */	
	private final String scriptLoggedOutIndicator;
	
	
	
	/** post data used to request the login URL without credentials */
	private final String postData;
	
	/** cookie requiered to request the login URL*/
	private final String cookie;
	
	/** Authentication information for conduct spider as a user*/
	
	/** user name for authentication (FormBasedAuthentication)*/
	private final String formUsername;

	/** Password for the defined user */
	private final String formPassword;
	
	/** user name for authentication (scriptBasedAuthentication)*/
	private final String scriptUsername;

	/** Password for the defined user */
	private final String scriptPassword;
	
	
	/** user name parameter user for authentication*/
	private final String usernameParameter;

	/** Password parameter used for the defined user */
	private final String passwordParameter;
	
	
	
	
	
	
	/** Realize a url AjaxSpider or not by ZAProxy using credentials*/
	private final boolean ajaxSpiderURLAsUser;

	/** Realize a url scan or not by ZAProxy using credentials */
	private final boolean scanURLAsUser;
	
	/** Save reports or not */
	private final boolean saveReports;

	/** List of chosen format for reports.
	 * ArrayList because it needs to be Serializable (whereas List is not Serializable)
	 */
	private final ArrayList<String> chosenFormats;
	
	/** Filename for ZAProxy reports. It can contain a relative path. */
	private final String filenameReports;
	
	/** Save session or not */
	private final boolean saveSession;
	
	/** Filename to save ZAProxy session. It can contain a relative path. */
	private final String filenameSaveSession; 
	
	/** The file policy to use for the scan. It contains only the policy name (without extension) */
	private final String chosenPolicy;
	
	/** Id of the newly created context*/
	private String contextId;

	/** Id of the newly created user*/
	private String userId;
	
	/** Id of the newly created scan*/
	private String scanId;

		
	//ce constructeur est ajoute par moi meme
	@DataBoundConstructor
	public ZAProxy(Boolean loadAuthenticationsScripts,String scanMode,String authenticationMode, String zapProxyHost, int zapProxyPort, String zapProxyKey,   int zapSSHPort, String  zapSSHUser,String  zapSSHPassword,boolean useWebProxy, String webProxyHost, int webProxyPort,
			String webProxyUser, String webProxyPassword, String filenameLoadSession, String targetURL,
			boolean spiderURL, boolean ajaxSpiderURL, boolean scanURL, boolean spiderAsUser, String scriptName,
			String loginUrl, String contextName, String includedUrl, String excludedUrl, String formLoggedInIndicator,
			String formLoggedOutIndicator, String scriptLoggedInIndicator, String scriptLoggedOutIndicator,String postData, String cookie, String usernameParameter, String passwordParameter,String formUsername, String formPassword,String scriptUsername, String scriptPassword
			, boolean ajaxSpiderURLAsUser, boolean scanURLAsUser, boolean saveReports, ArrayList<String> chosenFormats,
			String filenameReports, boolean saveSession, String filenameSaveSession, String chosenPolicy,
			String contextId, String userId, String scanId) {
		super();
		
		
		this.loadAuthenticationsScripts=loadAuthenticationsScripts;
		this.scanMode=scanMode;
		this.authenticationMode=authenticationMode;
		
		this.zapProxyHost = zapProxyHost;
		this.zapProxyPort = zapProxyPort;
		this.zapProxyKey = zapProxyKey;
		
 
		
		this.zapSSHPort=zapSSHPort;
		this.zapSSHUser=zapSSHUser;
		this.zapSSHPassword=zapSSHPassword;
		
		this.useWebProxy=useWebProxy;
		
		this.webProxyHost = webProxyHost;
		this.webProxyPort = webProxyPort;
		this.webProxyUser = webProxyUser;
		this.webProxyPassword = webProxyPassword;
		
		this.filenameLoadSession = filenameLoadSession;
		this.targetURL = targetURL;
		this.spiderURL = spiderURL;
		this.ajaxSpiderURL = ajaxSpiderURL;
		this.scanURL = scanURL;
		this.spiderAsUser = spiderAsUser;
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
		this.cookie = cookie;
		
		this.usernameParameter=usernameParameter;
		this.passwordParameter=passwordParameter;
		
		this.formUsername = formUsername;
		this.formPassword = formPassword;
		
		this.scriptUsername = scriptUsername;
		this.scriptPassword = scriptPassword;
		
		this.ajaxSpiderURLAsUser = ajaxSpiderURLAsUser;
		this.scanURLAsUser = scanURLAsUser;
		this.saveReports = saveReports;
		this.chosenFormats = chosenFormats;
		this.filenameReports = filenameReports;
		this.saveSession = saveSession;
		this.filenameSaveSession = filenameSaveSession;
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
		s += "zapProxyHost ["+zapProxyHost+"]\n";
		s += "zapProxyPort ["+zapProxyPort+"]\n";	
		s += "saveReports ["+saveReports+"]\n";
		s += "chosenFormats ["+chosenFormats+"]\n";
		s += "filenameReports ["+filenameReports+"]\n";
		s += "saveSession ["+saveSession+"]\n";
		s += "filenameSaveSession ["+filenameSaveSession+"]\n";		 
		s += "--------------------------------------------------";			 
		s += "filenameLoadSession ["+filenameLoadSession+"]\n";
		s += "--------------------------------------------------";
		s += "targetURL ["+targetURL+"]\n";
		s += "chosenPolicy ["+chosenPolicy+"]\n";
		s += "Authentication Script Name ["+scriptName+"]\n";
		s += "loginUrl ["+loginUrl+"]\n";
		s += "post Data ["+postData+"]\n";
		s += "cookie ["+cookie+"]\n";
		s += "formLoggedInIndicator ["+formLoggedInIndicator+"]\n";
		s += "formLoggedOutIndicator ["+formLoggedOutIndicator+"]\n";
		s += "scriptLoggedInIndicator ["+scriptLoggedInIndicator+"]\n";
		s += "scriptLoggedOutIndicator ["+scriptLoggedOutIndicator+"]\n";
		s += "--------------------------------------------------";
		s += "spiderURL ["+spiderURL+"]\n";
		s += "ajaxSpiderURL ["+ajaxSpiderURL+"]\n";
		s += "scanURL ["+scanURL+"]\n";
		s += "--------------------------------------------------";		
		s += "spider as user ["+spiderAsUser+"]\n";
		s += "ajaxSpiderURLAsUser ["+ajaxSpiderURLAsUser+"]\n";
		s += "scanURLAsUser ["+scanURLAsUser+"]\n";
		s += "--------------------------------------------------";	 
		s += "scriptUsername ["+scriptUsername+"]\n";
		s += "formUsername ["+formUsername+"]\n";
		s += "--------------------------------------------------";		
		
		return s;
	}
	
	
	// Overridden for better type safety.
	// If your plugin doesn't really define any property on Descriptor,
	// you don't have to do this.
	@Override
	public ZAProxyDescriptorImpl getDescriptor() {
		return (ZAProxyDescriptorImpl)super.getDescriptor();
	}
	
		
	/**
	 * @return the user
	 */
	public static String getUser() {
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
	 * @param scanId the scanId to set
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
	 * @return the cookie
	 */
	public String getCookie() {
		return cookie;
	}
	
	
	/*
	 * Getters allows to load members variables into UI.
	 */ 
 
	public String getFilenameLoadSession() {
		return filenameLoadSession;
	}

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

	public String getFilenameReports() {
		return filenameReports;
	}

	public boolean getSaveSession() {
		return saveSession;
	}

	public String getFilenameSaveSession() {
		return filenameSaveSession;
	} 
	
	public String getChosenPolicy() {
		return chosenPolicy;
	}
		
	public boolean getSpiderAsUser() {
		return spiderAsUser;
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
	 * @return the webProxyHost
	 */
	public String getWebProxyHost() {
		return webProxyHost;
	}

	/**
	 * @return the webProxyPort
	 */
	public int getWebProxyPort() {
		return webProxyPort;
	}

	/**
	 * @return the webProxyUser
	 */
	public String getWebProxyUser() {
		return webProxyUser;
	}

	/**
	 * @return the webProxyPassword
	 */
	public String getWebProxyPassword() {
		return webProxyPassword;
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
	 * @return the loadAuthenticationsScripts
	 */
	public Boolean getLoadAuthenticationsScripts() {
		return loadAuthenticationsScripts;
	}
	
	/**
	 * @return the fILE_SEPARATOR
	 */
	public String getFILE_SEPARATOR() {
		return FILE_SEPARATOR;
	}
	
	/**
	 * @return the zapSSHPort
	 */
	public int getZapSSHPort() {
		return zapSSHPort;
	}

	/**
	 * @return the zapSSHUser
	 */
	public String getZapSSHUser() {
		return zapSSHUser;
	}

	/**
	 * @return the zapSSHPassword
	 */
	public String getZapSSHPassword() {
		return zapSSHPassword;
	}

	/**
	 * @param zapSSHPort the zapSSHPort to set
	 */
	public void setZapSSHPort(int zapSSHPort) {
		this.zapSSHPort = zapSSHPort;
	}

	/**
	 * @param zapSSHUser the zapSSHUser to set
	 */
	public void setZapSSHUser(String zapSSHUser) {
		this.zapSSHUser = zapSSHUser;
	}

	/**
	 * @param zapSSHPassword the zapSSHPassword to set
	 */
	public void setZapSSHPassword(String zapSSHPassword) {
		this.zapSSHPassword = zapSSHPassword;
	}

	/**
	 * @param fILE_SEPARATOR the fILE_SEPARATOR to set
	 */
	public void setFILE_SEPARATOR(String fILE_SEPARATOR) {
		FILE_SEPARATOR = fILE_SEPARATOR;
	}
	/**
	 * @param loadAuthenticationsScripts the loadAuthenticationsScripts to set
	 */
	public void setLoadAuthenticationsScripts(Boolean loadAuthenticationsScripts) {
		this.loadAuthenticationsScripts = loadAuthenticationsScripts;
	}

	/**
	 * @param authenticationMode the authenticationMode to set
	 */
	public void setAuthenticationMode(String authenticationMode) {
		this.authenticationMode = authenticationMode;
	}

	/**
	 * @param scanMode the scanMode to set
	 */
	public void setScanMode(String scanMode) {
		this.scanMode = scanMode;
	}

	/*========================= SETTERS =============================*/
	/**
	 * @param zapProxyKey the zapProxyKey to set
	 */
	public void setZapProxyKey(String zapProxyKey) {
		this.zapProxyKey = zapProxyKey;
	}
	

	public void setZapProxyDirectory(String zapProxyDirectory) {
		// TODO Auto-generated method stub
		this.zapProxyDirectory=zapProxyDirectory;
	}
	public void setWebProxyHost(String webProxyHost) {
		
		this.webProxyHost=webProxyHost;
	}

	public void setWebProxyPort(int webProxyPort) {
	
		this.webProxyPort=webProxyPort;
	}

	public void setWebProxyUser(String webProxyUser) {
	
		this.webProxyUser=webProxyUser;
	}

	public void setWebProxyPassword(String webProxyPassword) {
		
		this.webProxyPassword=webProxyPassword;
	}

	/**
	 * @return the useWebProxy
	 */
	public boolean isUseWebProxy() {
		return useWebProxy;
	}

	/**
	 * @param useWebProxy the useWebProxy to set
	 */
	public void setUseWebProxy(boolean useWebProxy) {
		this.useWebProxy = useWebProxy;
	}
	

	/**
	 * @return the ajaxSpiderURLAsUser
	 */
	public boolean isAjaxSpiderURLAsUser() {
		return ajaxSpiderURLAsUser;
	}

	/**
	 * @return the scanURLAsUser
	 */
	public boolean isScanURLAsUser() {
		return scanURLAsUser;
	}
	
	/**
	 * @param contextId the contextId to set
	 */
	public void setContextId(String contextId) {
		this.contextId = contextId;
	}

	/**
	 * @param userId the userId to set
	 */
	public void setUserId(String userId) {
		this.userId = userId;
	}
	
	public void setZapProxyHost(String zapProxyHost) {
		this.zapProxyHost = zapProxyHost;
	}

	public void setZapProxyPort(int zapProxyPort) {
		this.zapProxyPort = zapProxyPort;
	}

	public void setZapProxyApiKey(String  zapProxyKey) {
		this.zapProxyKey = zapProxyKey;
	}
	
	/**
	 * Start ZAProxy using command line. It uses host and port configured in Jenkins admin mode and
	 * ZAProxy program is launched in daemon mode (i.e without UI).
	 * ZAProxy is started on the build's machine (so master machine ou slave machine) thanks to 
	 * {@link FilePath} object and {@link Launcher} object.
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param launcher the object to launch a process locally or remotely
	 * @throws InterruptedException 
	 * @throws IOException 
	 * @throws IllegalArgumentException 
	 */
	public void startZAP(AbstractBuild<?, ?> build, BuildListener listener, Launcher launcher) 
			throws IllegalArgumentException, IOException, InterruptedException {
		checkParams(build, listener);
		
		FilePath ws = build.getWorkspace();
	   
		if (ws == null) {
			Node node = build.getBuiltOn();
			if (node == null) {
				throw new NullPointerException("no such build node: " + build.getBuiltOnStr());
			}
			throw new NullPointerException("no workspace from node " + node + " which is computer " + node.toComputer() + " and has channel " + node.getChannel());
		}
		
		Node node = build.getBuiltOn();
		 
		
//		// Append zap program following Master/Slave and Windows/Unix
//		if( "".equals(node.getNodeName())) { // Master
//			if( File.pathSeparatorChar == ':' ) { // UNIX
//				this.setFILE_SEPARATOR("/");
//			} else { // Windows (pathSeparatorChar == ';')
//				this.setFILE_SEPARATOR("\\");
//			}
//		} 
//		else { // Slave
//			if( "Unix".equals(((SlaveComputer)node.toComputer()).getOSDescription()) ) {
//				this.setFILE_SEPARATOR("/");
//			} else {
//				this.setFILE_SEPARATOR("\\");
//			}
//		}
		 
		
//		// Contains the absolute path to ZAP program
//		FilePath zapPathWithProgName = new FilePath(ws.getChannel(), zapProgram + getZAPProgramNameWithSeparator(build));
//		listener.getLogger().println("Start ZAProxy [" + zapPathWithProgName.getRemote() + "]");
//		
//		// Command to start ZAProxy with parameters
//		List<String> cmd = new ArrayList<String>();
//		cmd.add(zapPathWithProgName.getRemote());
//		// TODO decommenter
//		//cmd.add(CMD_LINE_DAEMON);
//		cmd.add(CMD_LINE_HOST);
//		cmd.add(zapProxyHost);
//		cmd.add(CMD_LINE_PORT);
//		cmd.add(String.valueOf(zapProxyPort));
//		
//		// Set the default directory used by ZAP if it's defined and if a scan is provided
//		if(scanURL && zapDefaultDir != null && !zapDefaultDir.isEmpty()) {
//			cmd.add(CMD_LINE_DIR);
//			cmd.add(zapDefaultDir);
//		}
//		
//		// Adds command line arguments if it's provided
//		if(!cmdLinesZAP.isEmpty()) {
//			addZapCmdLine(cmd);
//		}
//			
//		EnvVars envVars = build.getEnvironment(listener);
//		// on Windows environment variables are converted to all upper case,
//		// but no such conversions are done on Unix, so to make this cross-platform,
//		// convert variables to all upper cases.
//		for(Map.Entry<String,String> e : build.getBuildVariables().entrySet())
//			envVars.put(e.getKey(),e.getValue());
//		
//		FilePath workDir = new FilePath(ws.getChannel(), zapProgram);
//		
//		// JDK choice
//		computeJdkToUse(build, listener, envVars);
//		
//		// Launch ZAP process on remote machine (on master if no remote machine)
//		launcher.launch().cmds(cmd).envs(envVars).stdout(listener).pwd(workDir).start();
//		
//		// Call waitForSuccessfulConnectionToZap(int, BuildListener) remotely
//		build.getWorkspace().act(new WaitZAProxyInitCallable(this, listener));
	}

	public boolean executeZAP(FilePath workspace, BuildListener listener) {
		
		
		
	 
		CustomZapClientApi zapClientAPI =new CustomZapClientApi(zapProxyHost,zapProxyPort, zapProxyKey, listener);
		boolean buildSuccess = true;
		
		
		
		// Try/catch here because I need to stopZAP in finally block and for that,
 
		try {
			
//			/* ======================================================= 
//			 * |                 start ZAP                       |
//			 * ======================================================= 
//			 */
//			if(startZAP){
//				
//				 
//				listener.getLogger().println("Starting ZAP remotely (SSH)");
//				listener.getLogger().println("SSH PORT : "+this.getZapSSHPort());
//				listener.getLogger().println("SSH USER : "+this.getZapSSHUser());
//			}
//			else {
//				listener.getLogger().println("Skip starting ZAP remotely");
//				listener.getLogger().println("startZAP : "+startZAPFirst);
//			}
//			if(startZAPFirst){
//				
//			 
//				listener.getLogger().println("Starting ZAP remotely (SSH)");
//				listener.getLogger().println("SSH PORT : "+this.getZapSSHPort());
//				listener.getLogger().println("SSH USER : "+this.getZapSSHUser());
//			}
//			else {
//				listener.getLogger().println("Skip starting ZAP remotely");
//				listener.getLogger().println("startZAPFirst : "+startZAPFirst);
//			}
			/* ======================================================= 
			 * |                 USE WEB PROXY                       |
			 * ======================================================= 
			 */
			if(useWebProxy){

				zapClientAPI.setWebProxyDetails(webProxyHost, webProxyPort, webProxyUser, webProxyPassword);
			}
			else {
				listener.getLogger().println("Skip using web proxy");
			}
			
			/* ======================================================= 
			 * |                ZAP FILE PATH SEPARATOR                       |
			 * ======================================================= 
			 */
			
			String zapHomeDirectory= zapClientAPI.getZapHomeDirectory();
			listener.getLogger().println("zapHomeDirectory : "+zapHomeDirectory);
			if(zapHomeDirectory.startsWith("/")){				
				this.setFILE_SEPARATOR("/");				
			}			
			else
			{
				this.setFILE_SEPARATOR("\\");
			}
			
			
			/* ======================================================= 
			 * |                  AUTHENTICATION SCRIPTS LIST                       |
			 * ======================================================= 
			 */
			
			if (loadAuthenticationsScripts){
				
				String scripstList=zapClientAPI.getScripts();
				File scriptsListFile = new File(workspace.getRemote(),authenticationScriptsListFile );
				listener.getLogger().println("/***************************** Liste des scripts d'authentification ****************************************/");
				listener.getLogger().println(scripstList);
				listener.getLogger().println("/***********************************************************************************************************/");
				
				FileUtils.writeByteArrayToFile(scriptsListFile, scripstList.getBytes());
				listener.getLogger().println("File ["+ scriptsListFile.getAbsolutePath() +"] saved");
			}
			else {
				listener.getLogger().println("Skip loading authentication Scripts List");
			
			/* ======================================================= 
			 * |                  LOAD SESSION                        |
			 * ======================================================= 
			 */
			if(filenameLoadSession != null && filenameLoadSession.length() != 0) {
				String sessionFile=zapProxyDirectory+"session"+getFILE_SEPARATOR()+workspace.getBaseName()+getFILE_SEPARATOR()+filenameSaveSession;
				//File sessionFile = new File(filenameLoadSession);
				listener.getLogger().println("Load session at ["+ sessionFile+"]");
				zapClientAPI.loadSession(sessionFile);
			} else {
				listener.getLogger().println("Skip loadSession");
			}
			
			
			
			/* ========================== PREPARE THE SCANNER ============================== */ 
			
			
		/* ============================================================================================= */	
			
			/* ======================================================= 
			 * |                  SET Up CONTEXT                         |
			 * ======================================================= 
			 */
			
				setUpContexte(zapClientAPI, listener);
				
			 /* ======================================================= 
			  * |                 SET UP SCANNER                          |
			  * ======================================================= 
			  */	
			
				setUpScanner(zapClientAPI, listener);				
				
			
	switch(scanMode) {
	
	case "NOT_AUTHENTICATED" : {
			listener.getLogger().println("SCANMOD : NOT_AUTHENTICATED");
			/* ======================================================= 
			 * |                  SPIDER URL                          |
			 * ======================================================= 
			 */
			if (spiderURL) {
				listener.getLogger().println("Spider the site [" + targetURL + "] without credentials");
				spiderURL(targetURL, zapClientAPI, listener);
			} else {
				listener.getLogger().println("Skip spidering the site [" + targetURL + "]");
			}

			/* ======================================================= 
			 * |                AJAX SPIDER URL                       |
			 * ======================================================= 
			 */
			if (ajaxSpiderURL) {
				listener.getLogger().println("Ajax Spider the site [" + targetURL + "] without credentials");
				ajaxSpiderURL(targetURL, listener, zapClientAPI);
			} else {
				listener.getLogger().println("Skip Ajax spidering the site [" + targetURL + "]");
			}
			/* ======================================================= 
			 * |                VIEW SPIDER RESULTS                       |
			 * ======================================================= 
			 */
			zapClientAPI.viewSpiderResults(scanId, listener);
			/* ======================================================= 
			 * |                  SCAN URL                            |
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
	
	case "AUTHENTICATED" :{
		   listener.getLogger().println("SCANMOD : AUTHENTICATED");
			/* =============================== MODE AVEC AUTHENTIFICATION ============================================================== */	
			
		   switch(authenticationMode)  {
		   
		   case "SCRIPT_BASED" : {
		   listener.getLogger().println("AUTHENTICATION_MOD :  : SCRIPT_BASED");
			setUpScriptBasedAuthenticationConf(zapClientAPI, listener);
			break;
		   }
		   
		   case "FORM_BASED" : {
			  listener.getLogger().println("AUTHENTICATION_MOD :  : FORM_BASED");
			 setUpFormBasedAuthenticationConf(zapClientAPI, listener);
			 break;
		   }
			 
			
		   }
			
			/* ======================================================= 
			 * |                  SPIDER URL AS USER                      |
			 * ======================================================= 
			 */
			if (spiderAsUser) {
				//listener.getLogger().println("Setting up Authentication");
				
				
				//setUpAuthentication(targetURL,listener,zapClientAPI,username,password,usernameParameter,passwordParameter,loginUrl,loggedInIndicator);
				
				listener.getLogger().println("Spider the site [" + targetURL + "] As User ["+userId+"]");					
				
				spiderURLAsUser(targetURL, listener, zapClientAPI, this.getContextId(), this.getUserId());			
				
				
			} else {
				listener.getLogger().println("Skip spidering the site [" + targetURL + "] As User ["+userId+"]");
			}
			
			
			/* ======================================================= 
			 * |                AJAX SPIDER URL AS USER                       |
			 * ======================================================= 
			 */
			if (ajaxSpiderURLAsUser) {
				listener.getLogger().println("Ajax Spider the site [" + targetURL + "] As User ["+userId+"]");
				ajaxSpiderURL(targetURL, listener, zapClientAPI);
			} else {
				listener.getLogger().println("Skip Ajax spidering the site [" + targetURL + "] As User ["+userId+"]");
			}
			
			/* ======================================================= 
			 * |                VIEW SPIDER RESULTS                       |
			 * ======================================================= 
			 */
			zapClientAPI.viewSpiderResults(scanId, listener);
			
			/* ======================================================= 
			 * |                  SCAN URL  As USER                          |
			 * ======================================================= 
			 */
			if (scanURLAsUser) {				
				listener.getLogger().println("Scan the site [" + targetURL + "] As user ["+userId+"]");
				scanURLAsUser(targetURL, listener, zapClientAPI);
				 
			} else {
				listener.getLogger().println("Skip scanning the site [" + targetURL + "] As User ["+userId+"]");
			}
			
			break;
			
			}
			/* ======================================= ACTIONS POST AUDIT ====================================================== */
			
			}
			
			/* ======================================================= 
			 * |                  SAVE REPORTS                        |
			 * ======================================================= 
			 */
			if (saveReports) {			
				// Generates reports for all formats selected
				for(String format : chosenFormats) {
					//ZAPreport report = ZAPreportCollection.getInstance().getMapFormatReport().get(format);
					saveReport(format, listener, workspace, zapClientAPI);
				}
			}
			
			/* ======================================================= 
			 * |                  SAVE SESSION                        |
			 * ======================================================= 
			 */
			if(saveSession) {
				if(filenameSaveSession != null && !filenameSaveSession.isEmpty()) {
				 
					//File sessionFile = new File(workspace.getRemote(), filenameSaveSession);
					//File sessionFile = new File(zapProxyDirectory+workspace.getBaseName()+"/session/", filenameSaveSession);
					String sessionFile=zapProxyDirectory+"session"+getFILE_SEPARATOR()+workspace.getBaseName()+getFILE_SEPARATOR()+filenameSaveSession;
					
					//write session to file = à toi de jouer
					
					
					
					
					
					
					
					
					//listener.getLogger().println("Save session to ["+ sessionFile.getAbsolutePath() +"]");
					listener.getLogger().println("Save session to ["+ sessionFile +"]"); 
//					
//					// Path creation if it doesn't exist
//					if(!sessionFile.getParentFile().exists()) {
//						sessionFile.getParentFile().mkdirs();
//					}
					
					// Method signature : saveSession(String apikey, String name, String overwrite)
		 			//zapClientAPI.saveSession(sessionFile.getAbsolutePath(), "true", listener);
					String status = zapClientAPI.saveSession(sessionFile, "true", listener);
					
					if (status.equals("OK")){
						
					//write session name to localfile sessionsListFile				
					File file = new File(workspace.getRemote(), sessionsListFile);
					FileUtils.writeStringToFile(file, filenameSaveSession+".session\n",true);
					listener.getLogger().println("File ["+ file.getAbsolutePath() +"] saved");
							
						
					}
				} 
			} else {
				listener.getLogger().println("Skip saveSession");
			}
			
			}
		} catch (Exception e) {
			listener.error(ExceptionUtils.getStackTrace(e));
			buildSuccess = false;
		} 
		finally {
		
				stopZAP(zapClientAPI, listener);
		
				buildSuccess = false;
			
		}
		return buildSuccess;
	}
	
	 /**
     * Test if the test type names match (for marking the radio button).
     * @param testTypeName The String representation of the test type.
     * @return Whether or not the test type string matches.
     */
    public String isScanMode(String testTypeName) {
        return this.scanMode.equalsIgnoreCase(testTypeName) ? "true" : "";
    }
    
    
    
    public String isAuthenticationMode(String testTypeName) {
        return this.authenticationMode.equalsIgnoreCase(testTypeName) ? "true" : "";
    }
 
 

	/**
	 * @param spiderURL the spiderURL to set
	 */
	public void setSpiderURL(boolean spiderURL) {
		this.spiderURL = spiderURL;
	}

	/**
	 * Verify parameters of the build setup are correct (null, empty, negative ...)
	 * 
	 * @param build
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws InterruptedException 
	 * @throws IOException 
	 * @throws Exception throw an exception if a parameter is invalid.
	 */
	private void checkParams(AbstractBuild<?, ?> build, BuildListener listener) throws IllegalArgumentException, IOException, InterruptedException {		 
		
//		if(targetURL == null || targetURL.isEmpty()) {
//			throw new IllegalArgumentException("targetURL is missing");
//		} else
//			listener.getLogger().println("targetURL = " + targetURL);

		if(zapProxyHost == null || zapProxyHost.isEmpty()) {
			throw new IllegalArgumentException("zapProxy Host is missing");
		} else
			listener.getLogger().println("zapProxyHost = " + zapProxyHost);

		if(zapProxyPort < 0) {
			throw new IllegalArgumentException("zapProxy Port is less than 0");
		} else
			listener.getLogger().println("zapProxyPort = " + zapProxyPort);
		
		if(zapProxyKey == null) {
			throw new IllegalArgumentException("zapProxy API Key is missing");
		} else
			listener.getLogger().println("zapProxyKey = " + zapProxyKey);
		
		
		
	}
		
 
	/**
	 * Generates security report for one format. Reports are saved into build's workspace.
	 * 
	 * @param reportFormat the format of the report
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param workspace a {@link FilePath} representing the build's workspace
	 * @param clientApi the ZAP client API to call method
	 * @throws ClientApiException 
	 * @throws IOException
	 */
	private void saveReport(String  format, BuildListener listener, FilePath workspace, CustomZapClientApi clientApi)   {
		
		final String fullFileName = filenameReports + "." + format;
		File reportsFile = new File(workspace.getRemote(), fullFileName);
		 
		switch (format ) {
		
		case "xml" :{
			try {
				FileUtils.writeByteArrayToFile(reportsFile, clientApi.generateXmlReport());
				listener.getLogger().println("File ["+ reportsFile.getAbsolutePath() +"] saved");
				break;
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (ClientApiException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}  
			
		}
			
		case "html" :{
			try {
				FileUtils.writeByteArrayToFile(reportsFile, clientApi.generateHtmlReport());
				listener.getLogger().println("File ["+ reportsFile.getAbsolutePath() +"] saved");
				break;
			} catch (IOException | ClientApiException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			
			
		}
			
		}
		
		
		
	}
 
	
	
 
	private void setUpScanner(CustomZapClientApi zapClientAPI,  BuildListener listener){
/************************ PREPARATION DU SCANNER **********************/
		
		zapClientAPI.includeInContext(includedUrl,contextName, listener);	
				
		if(!excludedUrl.equals("")){
			zapClientAPI.excludeFromContext(excludedUrl,contextName, listener);
		}
		
		zapClientAPI.enableAllScanner(chosenPolicy, listener );
		
		
		/*********************************************************************/
		zapClientAPI.setPolicyAttackStrength("0", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAttackStrength( "1", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAttackStrength("2", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAttackStrength("3", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAttackStrength( "4", "HIGH", chosenPolicy);
		
		/*********************************************************************/
		zapClientAPI.setPolicyAlertThreshold( "0", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAlertThreshold( "1", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAlertThreshold( "2", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAlertThreshold( "3", "HIGH", chosenPolicy);
		zapClientAPI.setPolicyAlertThreshold( "4", "HIGH", chosenPolicy);
		
		/*********************************************************************/
		zapClientAPI.setOptionPostForm( true);
		zapClientAPI.setOptionProcessForm( true);	
		zapClientAPI.setOptionHandleODataParametersVisited(true);
		zapClientAPI.setOptionShowAdvancedDialog(true);
		
		zapClientAPI.setOptionParseComments(true);
		zapClientAPI.setOptionParseRobotsTxt(true);
		zapClientAPI.setOptionParseSitemapXml(true);
		
		/*********************************************************************/
		
		
		//test.PassiveScanDisableAllScanner();
		zapClientAPI.PassiveScanEnableAllScanner(listener);
	}

 
	private void setUpContexte(CustomZapClientApi zapClientAPI,  BuildListener listener){
		
		 		
		listener.getLogger().println(zapClientAPI.getContextList());		 
		//récupère l'id du contexte si celui là est crée sinon elle le crée et retourne son id 
		String contextId=zapClientAPI.getContextId(contextName, listener);		
		this.setContextId(contextId);
		listener.getLogger().println("ContextId : "+contextId);		
		
		
	}
	
	/**
	 * Set up all authentication details
	 * @author Abdellah
	 * @param username user name to be used in authentication
	 * @param password password for the authentication user
	 * @param usernameParameter parameter define in passing username
	 * @param passwordParameter parameter that define in passing password for the user
	 * @param loginUrl login page url
	 * @param loggedInIdicator indication for know its logged in
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 * @throws UnsupportedEncodingException
	 */
	private void setUpScriptBasedAuthenticationConf(CustomZapClientApi zapClientAPI, BuildListener listener){
		
		 
		/***************** AUTHENTIFICATION ********************/
		listener.getLogger().println("---------------------------------------");
		//test.setFormBasedAuthentication(api,contextId );
		//{"error":"false","engine":"Rhino","description":"","name":"b.espaceclientv3.orange.fr.js","type":"authentication"}
		//String LoginUrl,String postData, String Cookie, String scriptName 
		zapClientAPI.setScriptBasedAuthentication(contextId,scriptName, listener);
		
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedInIndicator(contextId,scriptLoggedInIndicator,listener);
		
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedOutIndicator(contextId,scriptLoggedOutIndicator,listener) ;
		
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.listUserConfigInformation(contextId,listener);
		
		listener.getLogger().println("---------------------------------------");
		//String user, String username, String password
		String userid=zapClientAPI.setUserScriptAuthConfig(contextId,user, scriptUsername, scriptPassword,listener);
		this.setUserId(userid);
		
		zapClientAPI.enableUser( contextId, userid,listener);
		
		/*********************** Forced User **********************************/
		//https://groups.google.com/forum/#!topic/zaproxy-users/GRtzMJ4WJzk
		//pour que la partie ajaxSpider se fasse d'une manière authentifiée il faut activer et renseigner le ForcedUser 
		zapClientAPI.isForcedUserModeEnabled(listener);
		zapClientAPI.setForcedUser( contextId, userid,listener);
		zapClientAPI.getForcedUser(contextId,listener);
		zapClientAPI.setForcedUserModeEnabled( true,listener);
		zapClientAPI.isForcedUserModeEnabled(listener);
		
		
		
		/*********************************************************************/
		
		}
	
	
	/**
	 * Set up all authentication details
	 * @author Abdellah
	 * @param username user name to be used in authentication
	 * @param password password for the authentication user
	 * @param usernameParameter parameter define in passing username
	 * @param passwordParameter parameter that define in passing password for the user
	 * @param loginUrl login page url
	 * @param loggedInIdicator indication for know its logged in
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 * @throws UnsupportedEncodingException
	 */
	private void setUpFormBasedAuthenticationConf(CustomZapClientApi zapClientAPI, BuildListener listener){
		
		 
		/***************** AUTHENTIFICATION ********************/
		listener.getLogger().println("---------------------------------------");
		//test.setFormBasedAuthentication(api,contextId );
		//{"error":"false","engine":"Rhino","description":"","name":"b.espaceclientv3.orange.fr.js","type":"authentication"}
		//String LoginUrl,String postData, String Cookie, String scriptName 
		zapClientAPI.setUpFormBasedAuthentication(contextId,loginUrl,postData,usernameParameter,passwordParameter, listener);
		
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedInIndicator(contextId,formLoggedInIndicator,listener);
		
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.setLoggedOutIndicator(contextId,formLoggedOutIndicator,listener) ;
		
		listener.getLogger().println("---------------------------------------");
		zapClientAPI.listUserConfigInformation(contextId,listener);
		
		listener.getLogger().println("---------------------------------------");
		//String user, String username, String password
//		listener.getLogger().println("usernameParameter : "+usernameParameter);
//		listener.getLogger().println("passwordParameter : "+passwordParameter);
		String userid=zapClientAPI.setUserFormAuthConfig(contextId,user,formUsername, formPassword,listener);
		this.setUserId(userid);
		
		zapClientAPI.enableUser( contextId, userid,listener);
		
		/*********************** Forced User **********************************/
		//https://groups.google.com/forum/#!topic/zaproxy-users/GRtzMJ4WJzk
		//pour que la partie ajaxSpider se fasse d'une manière authentifiée il faut activer et renseigner le ForcedUser 
		zapClientAPI.isForcedUserModeEnabled(listener);
		zapClientAPI.setForcedUser( contextId, userid,listener);
		zapClientAPI.getForcedUser(contextId,listener);
		zapClientAPI.setForcedUserModeEnabled( true,listener);
		zapClientAPI.isForcedUserModeEnabled(listener);
		
		
		
		/*********************************************************************/
		
		}
	
	
 
	private void spiderURL(final String url, CustomZapClientApi zapClientAPI,BuildListener listener) 
			throws  InterruptedException {
		// Method signature : scan(String key, String url, String maxChildren, String recurse)
	 		String scanId=zapClientAPI.spiderURL(url, "",listener);
		this.setScanId(scanId);
 
	}
	/**
	 * Search for all links and pages on the URL and raised passives alerts
	 * @author thilina27
	 * @param url the url to investigate
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @throws ClientApiException
	 * @throws InterruptedException
	 */
	 
	private void spiderURLAsUser(final String url, BuildListener listener, CustomZapClientApi zapClientAPI, 
				String contextId, String userId)
				throws InterruptedException {
		
		
		
		
		
		String scanId=zapClientAPI.spiderAsUserURL(url, this.getContextId(), this.getUserId(), "0", listener);
		this.setScanId(scanId);
 
	}


	/**
	 * Search for all links and pages on the URL and raised passives alerts
	 * @author thilina27
	 * @param url the url to investigate
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 */
	private void ajaxSpiderURL(final String url, BuildListener listener, CustomZapClientApi zapClientAPI) 
			throws InterruptedException{
 
		zapClientAPI.ajaxSpiderURL(url,"false", listener);
 
	}
	
	/**
	 * Scan all pages found at url and raised actives alerts
	 *
	 * @param url the url to scan
	 * @param listener the listener to display log during the job execution in jenkins
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @throws ClientApiException
	 * @throws InterruptedException 
	 */
	private void scanURL(final String url, BuildListener listener, CustomZapClientApi zapClientAPI) 
			 throws InterruptedException {
		if(chosenPolicy == null || chosenPolicy.isEmpty()) {
			listener.getLogger().println("Scan url [" + url + "] with the policy by default");		
		} else {
			listener.getLogger().println("Scan url [" + url + "] with the following policy ["
							+ chosenPolicy + "]");
		}
 		
		zapClientAPI.scanURL(url, this.getScanId(), chosenPolicy, listener);
 
	}
	
	private void scanURLAsUser(final String url, BuildListener listener, CustomZapClientApi zapClientAPI) 
			 throws InterruptedException {
		if(chosenPolicy == null || chosenPolicy.isEmpty()) {
			listener.getLogger().println("Scan url [" + url + "] with the policy by default As User");		
		} else {
			listener.getLogger().println("Scan url [" + url + "] As User with the following policy ["
							+ chosenPolicy + "]");
		}
 
		zapClientAPI.scanURLAsUser(url, this.getScanId(), this.getContextId(), this.getUserId(), "true", chosenPolicy, listener);
 
	}
	
	/**
	 * Stop ZAproxy if it has been previously started.
	 * 
	 * @param zapClientAPI the client API to use ZAP API methods
	 * @param listener the listener to display log during the job execution in jenkins
	 * @throws ClientApiException 
	 */
	private void stopZAP(CustomZapClientApi zapClientAPI, BuildListener listener)  {
		if (zapClientAPI != null) {
			listener.getLogger().println("Shutdown ZAProxy"); 
			zapClientAPI.stopZap(zapProxyKey, listener);
		} else {
			listener.getLogger().println("No shutdown of ZAP (zapClientAPI==null)");
		}
	}
	
	
	/**
	 * Descriptor for {@link ZAProxy}. Used as a singleton.
	 * The class is marked as public so that it can be accessed from views.
	 *
	 * <p>
	 * See <tt>src/main/resources/fr/novia/zaproxyplugin/ZAProxy/*.jelly</tt>
	 * for the actual HTML fragment for the configuration screen.
	 */
	@Extension
	public static class ZAProxyDescriptorImpl extends Descriptor<ZAProxy> implements Serializable {
		
		private static final long serialVersionUID = 4028279269334325901L;
		
		/**
		 * To persist global configuration information,
		 * simply store it in a field and call save().
		 *
		 * <p>
		 * If you don't want fields to be persisted, use <tt>transient</tt>.
		 */
		
		/** Map where key is the report format represented by a String
		 *  and value is a ZAPreport object allowing to generate a report with the corresponding format.
		 */
		private Map<String, ZAPreport> mapFormatReport;
		
		/** Represents the build's workspace */
		private FilePath workspace;
		
		/**
		 * In order to load the persisted global configuration, you have to
		 * call load() in the constructor.
		 */
		public ZAProxyDescriptorImpl() {
			mapFormatReport = ZAPreportCollection.getInstance().getMapFormatReport();
			load();
		}
		
		@Override
		public String getDisplayName() { 
			return null; 
		}

		public Map<String, ZAPreport> getMapFormatReport() {
			return mapFormatReport;
		}
		
		public List<String> getAllFormats() {
			return new ArrayList<String>(mapFormatReport.keySet());
		}
		
		public void setWorkspace(FilePath ws) {
			this.workspace = ws;
		}
		
		/**
		 * Performs on-the-fly validation of the form field 'filenameReports'.
		 *
		 * @param filenameReports
		 *      This parameter receives the value that the user has typed.
		 * @return
		 *      Indicates the outcome of the validation. This is sent to the browser.
		 *      <p>
		 *      Note that returning {@link FormValidation#error(String)} does not
		 *      prevent the form from being saved. It just means that a message
		 *      will be displayed to the user.
		 */
		public FormValidation doCheckFilenameReports(@QueryParameter("filenameReports") final String filenameReports) {
			if(filenameReports.isEmpty())
				return FormValidation.error("Field is required");
			if(!FilenameUtils.getExtension(filenameReports).isEmpty())
				return FormValidation.warning("A file extension is not necessary.");
			return FormValidation.ok();
		}
		
		/**
		 * Performs on-the-fly validation of the form field 'filenameSaveSession'.
		 * <p>
		 * If the user wants to save session whereas a session is already loaded, 
		 * the relative path to the saved session must be different from the relative path to the loaded session.
		 *
		 * @param filenameLoadSession
		 *      Parameter to compare with filenameSaveSession.
		 * @param filenameSaveSession
		 *      This parameter receives the value that the user has typed.
		 * @return
		 *      Indicates the outcome of the validation. This is sent to the browser.
		 *      <p>
		 *      Note that returning {@link FormValidation#error(String)} does not
		 *      prevent the form from being saved. It just means that a message
		 *      will be displayed to the user.
		 */
		public FormValidation doCheckFilenameSaveSession(
				@QueryParameter("filenameLoadSession") final String filenameLoadSession,
				@QueryParameter("filenameSaveSession") final String filenameSaveSession) {
			// Contains just the name of the session (without workspace path and extension)
			String cleanFilenameLoadSession = null;
			if(workspace != null) {
				cleanFilenameLoadSession = filenameLoadSession
						.replace(workspace.getRemote(), "") // Remove workspace path
						.replaceFirst("\\\\", "") // Remove separator after workspace path if windows
						.replaceFirst("/", ""); // Remove separator after workspace path if Unix
					
				if(!cleanFilenameLoadSession.isEmpty() && 
						(filenameSaveSession.equals(cleanFilenameLoadSession) 
								|| filenameSaveSession.equals(cleanFilenameLoadSession.replace(FILE_SESSION_EXTENSION, ""))) )
					return FormValidation.error("The saved session filename is the same of the loaded session filename.");
			}
			
			if(!filenameLoadSession.isEmpty())
				return FormValidation.warning("A session is loaded, so it's not necessary to save session");
			
			if(!FilenameUtils.getExtension(filenameSaveSession).isEmpty())
				return FormValidation.warning("A file extension is not necessary. A default file extension will be added (.session)");
			return FormValidation.ok();
		}
		
		/**
		 * List model to choose the alert report format
		 * 
		 * @return a {@link ListBoxModel}
		 */
		public ListBoxModel doFillChosenFormatsItems() {
			ListBoxModel items = new ListBoxModel();
			for(String format: mapFormatReport.keySet()) {
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
			 
			//hudson.FilePath workspace = hudson.model.Executor.currentExecutor().getCurrentWorkspace();
			// No workspace before the first build, so workspace is null
			if(workspace != null) {
				Collection<String> sessionsInString = workspace.act(new FileCallable<Collection<String>>() {
					private static final long serialVersionUID = 1328740269013881941L;
	
					public Collection<String> invoke(File f, VirtualChannel channel) throws IOException {
						
						// List all files with FILE_SESSION_EXTENSION on the machine where the workspace is located
						Collection<File> colFiles = FileUtils.listFiles(f,
								FileFilterUtils.suffixFileFilter(FILE_SCRIPTS_EXTENSION),
								TrueFileFilter.INSTANCE);
						
						Collection<String> colString = new ArrayList<String>();
						
						// "Transform" File into String
						for (File file : colFiles) {
							for (String line : FileUtils.readLines(file)) {
							colString.add(line);
							//colString.add(file.getAbsolutePath());
							// The following line is to remove the full path to the workspace,
							// keep just the relative path to the session
							//colString.add(file.getAbsolutePath().replace(workspace.getRemote() + File.separatorChar, ""));
						
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
				
				items.add("workspace is null : lancer le build pour récupérre la liste des scripts d'authentification");
				 
			}
			
			
			return items;
//	ListBoxModel m=new ListBoxModel();
//	m.add("Merci de choisir un script d'authentification","");
//	//hudson.FilePath workspace = hudson.model.Executor.currentExecutor().getCurrentWorkspace();
////	  Collection<String> allJobs=Hudson.getInstance().getNodeName();
////	  for (  String job : allJobs) {
////	    m.add(job);
////	  }
//	  
//
//	  m.add( "Jenkins workspace :"+Jenkins.getInstance().getRawWorkspaceDir());
//	  m.add( "Jenkins rootDir :"+Jenkins.getInstance().getRootDir().getAbsolutePath());
//	  m.add( "Jenkins workspace :"+Jenkins.getInstance().getRootPath().getBaseName());
//	  return m;
			
		}
		
		/**
		 * List model to choose the ZAP session to use. It's called on the remote machine (if present)
		 * to load all session files in the build's workspace.
		 * 
		 * @return a {@link ListBoxModel}. It can be empty if the workspace doesn't contain any ZAP sessions.
		 * @throws InterruptedException 
		 * @throws IOException 
		 */
		public ListBoxModel doFillFilenameLoadSessionItems() throws IOException, InterruptedException {
			ListBoxModel items = new ListBoxModel();
			
			// No workspace before the first build, so workspace is null
			if(workspace != null) {
				Collection<String> sessionsInString = workspace.act(new FileCallable<Collection<String>>() {
					private static final long serialVersionUID = 1328740269013881941L;
	
					public Collection<String> invoke(File f, VirtualChannel channel) throws IOException {
						
						// List all files with FILE_SESSION_EXTENSION on the machine where the workspace is located
						Collection<File> colFiles = FileUtils.listFiles(f,
								FileFilterUtils.suffixFileFilter(FILE_SESSION_EXTENSION),
								TrueFileFilter.INSTANCE);
						
						Collection<String> colString = new ArrayList<String>();
						
						for (File file : colFiles) {
							for (String line : FileUtils.readLines(file)) {
							if(!colString.contains(line)){	
								colString.add(line);
							}
							//colString.add(file.getAbsolutePath());
							// The following line is to remove the full path to the workspace,
							// keep just the relative path to the session
							//colString.add(file.getAbsolutePath().replace(workspace.getRemote() + File.separatorChar, ""));
						
							}
							}
						return colString;
					}
						
						
						
						
						
//						
//						// "Transform" File into String
//						for (File file : colFiles) {
//							colString.add(file.getAbsolutePath());
//							// The following line is to remove the full path to the workspace,
//							// keep just the relative path to the session
//							//colString.add(file.getAbsolutePath().replace(workspace.getRemote() + File.separatorChar, ""));
//						}
//						return colString;
//					}
	
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
			else {
				
				items.add("workspace is null");
			}
			
			return items;
		}
	
		
//		/**
//		 * List model to choose the tool used (normally, it should be the ZAProxy tool).
//		 * 
//		 * @return a {@link ListBoxModel}
//		 */
//		public ListBoxModel doFillToolUsedItems() {
//			ListBoxModel items = new ListBoxModel();
//			for(ToolDescriptor<?> desc : ToolInstallation.all()) {
//				for (ToolInstallation tool : desc.getInstallations()) {
//					items.add(tool.getName());
//				}
//			}
//			return items;
//		}
//		
 
	}




	
	
 
 
}
