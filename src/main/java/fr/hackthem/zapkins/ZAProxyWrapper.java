package fr.hackthem.zapkins;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Hudson;
import hudson.tasks.BuildWrapper;
import hudson.tasks.BuildWrapperDescriptor;
import hudson.util.FormValidation;
import net.sf.json.JSONObject;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.kohsuke.stapler.export.ExportedBean;
import org.zaproxy.clientapi.core.ClientApiException;
import com.jcraft.jsch.JSchException; 
import fr.hackthem.zapkins.api.CustomZapClientApi;
import fr.hackthem.zapkins.utilities.HttpUtilities;
import fr.hackthem.zapkins.utilities.ProxyAuthenticator;
import fr.hackthem.zapkins.utilities.SSHConnexion;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Scanner;

@ExportedBean
public class ZAProxyWrapper extends BuildWrapper implements Serializable {	

	private static final long serialVersionUID = -5641693402522157794L;
	
	private static final String ZAP_PROG_NAME_BAT = "zap.bat";
	private static final String ZAP_PROG_NAME_SH = "zap.sh";
	public static final String CMD_LINE_PORT = "-port";
	public static final String CMD_LINE_DAEMON = "-daemon";
	private final ZAProxy zaproxy;

    @DataBoundConstructor
    public ZAProxyWrapper(  ZAProxy zaproxy) {
    	
    	this.zaproxy=zaproxy;       
    }
    
    
    public ZAProxy getZaproxy() {
        return zaproxy;
    }
 

    @Override
    public Environment setUp(AbstractBuild build, Launcher launcher, BuildListener listener) throws IOException, InterruptedException {
	 
    	final CustomZapClientApi zapClientAPI=zaproxy.executeZAP( build, launcher,listener)  ;
        
        	 
		 
        return new Environment() {

            @Override
            public void buildEnvVars(Map<String, String> env) {
 
            }

            @Override
            public boolean tearDown(AbstractBuild build, BuildListener listener) {
                try {
                    zaproxy.stopZAP(zapClientAPI, listener);
                } catch (ClientApiException e) {
                    listener.error(ExceptionUtils.getStackTrace(e));
                    return false;
                }
                return true;
            }
        };

    }

    @Extension    
   
	public static final ZAProxyWrapperDescriptorImpl DESCRIPTOR = new ZAProxyWrapperDescriptorImpl();
    
    public static final class ZAProxyWrapperDescriptorImpl extends BuildWrapperDescriptor implements Serializable {
 
		private static final long serialVersionUID = 4714962003295700499L;
	 
		/**
		 * To persist global configuration information, simply store it in a
		 * field and call save().
		 *
		 * <p>
		 * If you don't want fields to be persisted, use <tt>transient</tt>.
		 */
		private String defaultProtocol;
		
		private String zapProxyDefaultHost;	
		
		/** API Key configured when ZAProxy is used as proxy */
		private String zapProxyDefaultApiKey;
		
		private int zapProxyDefaultTimeoutInSec;

		/** ZAP default Directory configured when ZAProxy is used as proxy */
		private String zapDefaultDirectory;

		private boolean useWebProxy;
		
		private String webProxyHost;
		
		private int webProxyPort;
		
		private String webProxyUser;
		
		private String webProxyPassword;

		private String zapInstallationType;
		
		private boolean  startZAPFirst;

		/** ZAP default SSH port configured when ZAProxy is used as proxy */
		private int zapDefaultSSHPort;
		
		/** ZAP default SSH port configured when ZAProxy is used as proxy */
		private String zapDefaultSSHUser;
		
		/** ZAP default SSH port configured when ZAProxy is used as proxy */
		private String zapDefaultSSHPassword;
		
		private int zapProxyDefaultTimeoutSSHInSec;

		private boolean stopZAPAtEnd;

		private String authorizedURLs;		
		
		/** Realize a url spider or not by ZAProxy */
		private boolean spiderURL;

		/** Realize a url AjaxSpider or not by ZAProxy */
		private  boolean ajaxSpiderURL;

		/** Realize a url scan or not by ZAProxy */
		private  boolean scanURL;
		
		/** fix ZAP port number for debugging**/
		private boolean debugMod;
		/** fix the value of ZAP port number for debugging **/
		private int debugPort;

		public ZAProxyWrapperDescriptorImpl() {
            super(ZAProxyWrapper.class);
            load();
        }

        @Override
        public String getDisplayName() {
            return "Start ZAProxy";
        }

        @Override
        public boolean isApplicable(AbstractProject<?, ?> item) {
            return true;
        }
        
		@Override
		public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
			// To persist global configuration information,
			// set that to properties and call save().

			defaultProtocol = formData.getString("defaultProtocol");
			zapProxyDefaultHost = formData.getString("zapProxyDefaultHost");			
			zapProxyDefaultApiKey = formData.getString("zapProxyDefaultApiKey");
			zapProxyDefaultTimeoutInSec = formData.getInt("zapProxyDefaultTimeoutInSec");
			zapDefaultDirectory = formData.getString("zapDefaultDirectory");
			useWebProxy = formData.getBoolean("useWebProxy");
			webProxyHost = formData.getString("webProxyHost");
			webProxyPort = formData.getInt("webProxyPort");
			webProxyUser = formData.getString("webProxyUser");
			webProxyPassword = formData.getString("webProxyPassword");
			startZAPFirst = formData.getBoolean("startZAPFirst");
			zapInstallationType = formData.getString("zapInstallationType");
			//zapLocation= formData.getString("zapLocation");
			zapDefaultSSHPort = formData.getInt("zapDefaultSSHPort");
			zapDefaultSSHUser = formData.getString("zapDefaultSSHUser");
			zapDefaultSSHPassword = formData.getString("zapDefaultSSHPassword");
			zapProxyDefaultTimeoutSSHInSec = formData.getInt("zapProxyDefaultTimeoutSSHInSec");
			stopZAPAtEnd = formData.getBoolean("stopZAPAtEnd");
			authorizedURLs = formData.getString("authorizedURLs");			
			spiderURL=formData.getBoolean("spiderURL");			
			ajaxSpiderURL=formData.getBoolean("ajaxSpiderURL");
			scanURL=formData.getBoolean("scanURL");
			debugMod=formData.getBoolean("debugMod");
			debugPort=formData.getInt("debugPort");

			// ^Can also use req.bindJSON(this, formData);
			// (easier when there are many fields; need set* methods for this,
			// like setUseFrench)
			save();
			return super.configure(req, formData);
		}
        
		/**
		 * @return the authorizedURL
		 */
		public String getAuthorizedURLs() {
			return authorizedURLs;
		}

		public int getZapProxyDefaultTimeoutInSec() {
			return zapProxyDefaultTimeoutInSec;
		}

		/**
		 * @return the zapProxyDefaultTimeoutSSHInSec
		 */
		public int getZapProxyDefaultTimeoutSSHInSec() {
			return zapProxyDefaultTimeoutSSHInSec;
		}

		public String getZapProxyDefaultHost() {
			return zapProxyDefaultHost;
		}

		public String getZapProxyDefaultApiKey() {
			return zapProxyDefaultApiKey;
		}

		public String getZapDefaultDirectory() {
			return zapDefaultDirectory;
		}

		/**
		 * @return the zapDefaultSSHPort
		 */
		public int getZapDefaultSSHPort() {
			return zapDefaultSSHPort;
		}

		/**
		 * @return the zapDefaultSSHUser
		 */
		public String getZapDefaultSSHUser() {
			return zapDefaultSSHUser;
		}

		/**
		 * @return the zapDefaultSSHPassword
		 */
		public String getZapDefaultSSHPassword() {
			return zapDefaultSSHPassword;
		}

		/**
		 * @return the defaultProtocol
		 */
		public String getDefaultProtocol() {
			return defaultProtocol;
		}

		/**
		 * @return the useWebProxy
		 */
		public boolean isUseWebProxy() {
			return useWebProxy;
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
		 * @return the zapInstallationType
		 */
		public String getZapInstallationType() {
			return zapInstallationType;
		}
		
		/**
		 * 
		 * @return startZAPFirst
		 */
		
		public boolean isStartZAPFirst(){
			
			return startZAPFirst;
		}

		/**
		 * @return the stopZAPAtEnd
		 */
		public boolean isStopZAPAtEnd() {
			return stopZAPAtEnd;
		}

		/**
		 * @return the spiderURL
		 */
		public boolean isSpiderURL() {
			return spiderURL;
		}

		/**
		 * @return the ajaxSpiderURL
		 */
		public boolean isAjaxSpiderURL() {
			return ajaxSpiderURL;
		}

		/**
		 * @return the scanURL
		 */
		public boolean isScanURL() {
			return scanURL;
		}

		/**
		 * 
		 * @return the debugMod
		 */
		public boolean isDebugMod(){
			return debugMod;
		}
		/**
		 * 
		 * @return the fixed value of port number
		 */
		public int getDebugPort(){
			return debugPort;
		}
		
		
		public String isZAPInstaltionLocation(String testTypeName){
			System.out.println("zapInstallationType : "+zapInstallationType);
			return this.zapInstallationType.equalsIgnoreCase(testTypeName) ? "true" : "";
			
		}
		
		
		
		public FormValidation doTestZAPConnection(
				@QueryParameter("defaultProtocol") final String protocol,
				@QueryParameter("useWebProxy") final boolean useWebProxy,
				@QueryParameter("webProxyHost") final String webProxyHost,
				@QueryParameter("webProxyPort") final int webProxyPort,
				@QueryParameter("webProxyUser") final String webProxyUser,
				@QueryParameter("webProxyPassword") final String webProxyPassword,
				
				@QueryParameter("zapDefaultDirectory") final String zapProxyDirectory,
				@QueryParameter("zapProxyDefaultHost") final String zapProxyHost,			
				@QueryParameter("zapProxyDefaultApiKey") final String zapProxyKey,
				@QueryParameter("zapProxyDefaultTimeoutInSec") final int timeoutInSec,
				
				@QueryParameter("zapInstallationType") final String zapLocation,
				
				@QueryParameter("zapDefaultSSHPort") final int zapSSHPort,
				@QueryParameter("zapDefaultSSHUser") final String zapSSHUser,
				@QueryParameter("zapDefaultSSHPassword") final String zapSSHPassword,
				@QueryParameter("zapProxyDefaultTimeoutSSHInSec") final int timeoutSSHInSec,
				
				@QueryParameter("debugMod") final boolean debugMod,
				@QueryParameter("debugPort") final int debugPort


		) {
			
			/*
			 * ======================================================= | USE WEB PROXY | =======================================================
			 */
			Proxy proxy = null;
			if (useWebProxy) {
				System.out.println("Using Web Proxy");
				Authenticator.setDefault(new ProxyAuthenticator(webProxyUser, webProxyPassword));
				// cet appel permet de ne pas généraliser le passage par le
				// proxy à tous les appels issus de la même JVM
				proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(webProxyHost, webProxyPort));
			}
			else {
				System.out.println("Skip Using Web Proxy");			}
			
			/*
			 * ======================================================= | CHOOSE A FREE PORT  | =======================================================			 */		
				
				
				int zapProxyPort = HttpUtilities.getPortNumber();				
				
				while(HttpUtilities.portIsToken(proxy, protocol, zapProxyHost, zapProxyPort, timeoutInSec)){
					
					zapProxyPort = HttpUtilities.getPortNumber();		}
				
				
				/*************** MOD DEBUG ***************************/
				
				if(debugMod){
				System.out.println("PORT[debugPort]: "+debugPort);
				System.out.println("PORT[zapProxyPort]: "+zapProxyPort);
				zapProxyPort=debugPort;	
				
				}				
				/*********************************************************************************************/				
				
				/*
				 * ======================================================= | start ZAP | =======================================================
				 * 
				 */
				final String sshLinuxCommand = "Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh " + zapProxyDirectory+ "zap.sh -daemon -port " + zapProxyPort;			
				
 
				switch(zapLocation){
				
								
				case "LOCALE" :				 	
					System.out.println("Starting ZAP locally");
					final int port = zapProxyPort;
					Thread t1 = new Thread(new Runnable() {
					    public void run()
					    {
					    	try {							
								 
								startZAPLocally(zapProxyDirectory, port) ;
							 
							} catch (IOException e1) {
								 
								e1.printStackTrace();
							} catch (InterruptedException e1) {
								 
								e1.printStackTrace();
								 
							}
			 
					    }});  
					    t1.start();	 
					
					break ;
					
				case "DISTANTE":
					System.out.println("Starting ZAP remotely (SSH)");	
					SSHConnexion.execCommandSshPasswordAuth(zapProxyHost, zapSSHPort, zapSSHUser, zapSSHPassword,HttpUtilities.getMilliseconds(timeoutSSHInSec),sshLinuxCommand );
					//TODO
					//SSHConnexion.execCommandSshKeydAuth(...
					
					System.out.println("connexion SSH : END");
					
			    default :
			    	break;
				} 
	 
				/*
				 * ======================================================= | WAITING ZAP STARTING | =======================================================
				 * 
				 */
			    HttpUtilities.waitForSuccessfulConnectionToZap(proxy,protocol, zapProxyHost, zapProxyPort,timeoutInSec);		
				
				/*
				 * ======================================================= | TESTING ZAP CONNECTION CONFIGURATION  | ======================================================
				 * 
				 */
			    
			    return CustomZapClientApi.testZAPConnection(protocol, zapProxyHost, zapProxyPort, zapProxyKey,proxy,timeoutInSec );		}
		
		
		
		/**
		 * Start ZAP locally
		 * @throws IOException 
		 * @throws InterruptedException 
		 */
		
		@SuppressWarnings("deprecation")
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
 
		public FormValidation doTestSSHConnection(

				@QueryParameter("zapProxyDefaultHost") final String zapProxyHost,
				@QueryParameter("zapDefaultSSHPort") final int zapSSHPort,
				@QueryParameter("zapDefaultSSHUser") final String zapSSHUser,
				@QueryParameter("zapDefaultSSHPassword") final String zapSSHPassword,
				@QueryParameter("zapProxyDefaultTimeoutSSHInSec") final int timeoutSSHInSec

		) {

	 
			/*
			 * ======================================================= | USE WEB PROXY | =======================================================
			 */

			try {
				SSHConnexion.testSSHPasswordAuth(zapProxyHost, zapSSHPort, zapSSHUser, zapSSHPassword,HttpUtilities.getMilliseconds(timeoutSSHInSec));
			} catch (JSchException e) {
				 
				e.printStackTrace();
				return FormValidation
						.error(e.getMessage() + " : Vérifier le login et le mot de passe de connextion SSH ! ");
			} catch (IOException e) {
				 
				e.printStackTrace();
				return FormValidation
						.error(e.getMessage() + " : Vérifier l'adresse du serveur SSH et le numéro de port !");
			}

			return FormValidation.okWithMarkup("<br><b><font color=\"green\">Connection réussie !</font></b><br>");		}
	       
        

    }


}