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

import hudson.Extension;
import hudson.FilePath;
import hudson.FilePath.FileCallable;
import hudson.Launcher.LocalLauncher;
import hudson.Launcher.ProcStarter;
import hudson.Launcher.RemoteLauncher;
import hudson.Proc;
import hudson.Launcher;
import hudson.model.BuildListener;
import hudson.model.Node;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.remoting.VirtualChannel;
import hudson.slaves.SlaveComputer;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.ArgumentListBuilder;
import hudson.util.FormValidation;
import fr.hackthem.zapkins.api.CustomZapClientApi;
import fr.hackthem.zapkins.ZAProxy;
import fr.hackthem.zapkins.utilities.HttpUtilities;
import fr.hackthem.zapkins.utilities.ProxyAuthenticator;
import fr.hackthem.zapkins.utilities.SSHConnexion;
import net.sf.json.JSONObject;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;
import org.kohsuke.stapler.StaplerRequest;
import org.xml.sax.SAXException;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ClientApiException;
import com.jcraft.jsch.JSchException;
import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import javax.xml.parsers.ParserConfigurationException;

/**
 * 
 * The main class of the plugin. This class adds a build step in a Jenkins job
 * that allows you to launch the ZAProxy security tool and get alerts reports
 * from it.
 * 
 * @author Abdellah AZOUGARH
 *
 */
public class ZAProxyBuilder extends Builder {

	private static final int MILLISECONDS_IN_SECOND = 1000;
	/** The objet to start and call ZAProxy methods */
	private final ZAProxy zaproxy;
	// On ne peut pas rendre ce champs final, car on ne peut l'initialiser à
	// travers le constructeur
	private BuildListener listener;

	@DataBoundConstructor
	public ZAProxyBuilder(ZAProxy zaproxy) {

		super();
		this.zaproxy = zaproxy;

	}

	public ZAProxy getZaproxy() {
		return zaproxy;
	}

	/**
	 * @return the listener
	 */
	public BuildListener getListener() {
		return listener;
	}
	// Overridden for better type safety.
	// If your plugin doesn't really define any property on Descriptor,
	// you don't have to do this.
	@Override
	public ZAProxyBuilderDescriptorImpl getDescriptor() {
		return (ZAProxyBuilderDescriptorImpl) super.getDescriptor();
	}

	// Method called before launching the build
	public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {

		return true;
	}

	// Methode appelée pendant le build, c'est ici que zap est lancé
	@Override
	public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {

		int zapProxyDefaultTimeoutSSHInSec = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultTimeoutSSHInSec();
		int zapProxyDefaultTimeoutInSec = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultTimeoutInSec();
		String defaultProtocol = ZAProxyBuilder.DESCRIPTOR.getDefaultProtocol();
		String zapProxyDefaultHost = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultHost();
		int zapDefaultSSHPort = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPort();
		String zapDefaultSSHUser = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHUser();
		String zapDefaultSSHPassword = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPassword();
		boolean useWebProxy = ZAProxyBuilder.DESCRIPTOR.isUseWebProxy();
		boolean startZAPFirst = ZAProxyBuilder.DESCRIPTOR.isStartZAPFirst();
		String webProxyHost = ZAProxyBuilder.DESCRIPTOR.getWebProxyHost();
		int webProxyPort = ZAProxyBuilder.DESCRIPTOR.getWebProxyPort();
		String webProxyUser = ZAProxyBuilder.DESCRIPTOR.getWebProxyUser();
		String webProxyPassword = ZAProxyBuilder.DESCRIPTOR.getWebProxyPassword();
		String zapDefaultDirectory = ZAProxyBuilder.DESCRIPTOR.getZapDefaultDirectory();		
		int zapProxyPort = 0;
			
		

		/*
		 * ======================================================= | USE WEB PROXY | =======================================================
		 */
		if (useWebProxy) {
			// Ici on généralise l'utilisation du proxy web à tous les appels
			// passés via la JVM
			listener.getLogger().println("Using web proxy");
			System.out.println("Using web proxy");
			CustomZapClientApi.setWebProxyDetails(webProxyHost, webProxyPort, webProxyUser, webProxyPassword);
		} else {
			listener.getLogger().println("Skip using web proxy");
			System.out.println("Skip using web proxy");
		}		

		if (startZAPFirst) {
			
			
			/*
			 * ======================================================= | CHOOSE A FREE PORT  | =======================================================
			 */
			
			
			zapProxyPort = HttpUtilities.getPortNumber();
			
			while(HttpUtilities.portIsToken(null, defaultProtocol, zapProxyDefaultHost, zapProxyPort, zapProxyDefaultTimeoutInSec, listener)){
				
				zapProxyPort = HttpUtilities.getPortNumber();
				
			}			
			
			zaproxy.setZapProxyPort(zapProxyPort);
			
			
			
			listener.getLogger().println("------- START Prebuild -------");
			System.out.println("------- START Prebuild -------");

			listener.getLogger().println("Perform ZAProxy");
			System.out.println("Perform ZAProxy");
			
			final String linuxCommand = "Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh " + zapDefaultDirectory+ "zap.sh -daemon -port " + zapProxyPort;
			final String WindowsCommand = zapDefaultDirectory + "zap.bat -daemon -port " + zapProxyPort;

			/*
			 * ======================================================= | start ZAP | =======================================================
			 */
			switch(zapProxyDefaultHost){
			
			case "localhost":
			case "127.0.0.1" :
				listener.getLogger().println("Starting ZAP locally");	
				System.out.println("Starting ZAP locally");
				ArgumentListBuilder command = new ArgumentListBuilder();				

				if(launcher.isUnix()){
					command.addTokenized(linuxCommand);
				}
				else {
					command.addTokenized(WindowsCommand);
				}
				
				ProcStarter ps = launcher.new ProcStarter();
				ps = ps.cmds(command).stdout(listener);
				try {
					ps = ps.pwd(build.getWorkspace()).envs(build.getEnvironment(listener));
					Proc proc = launcher.launch(ps);
					int retcode = proc.join();
					
					
					
				} catch (IOException | InterruptedException e) {
					// TODO Auto-generated catch block
					e.printStackTrace();
				}
				
				break ;
				
			default :
				listener.getLogger().println("Starting ZAP remotely (SSH)");	
				System.out.println("Starting ZAP remotely (SSH)");
				SSHConnexion.execCommand(zapProxyDefaultHost, zapDefaultSSHPort, zapDefaultSSHUser, zapDefaultSSHPassword,HttpUtilities.getMilliseconds(zapProxyDefaultTimeoutSSHInSec ),linuxCommand, listener);
	 
				
			}

			listener.getLogger().println("------- END Prebuild -------");
		}

		else {
			listener.getLogger().println("Skip starting ZAP remotely");
			listener.getLogger().println("startZAPFirst : " + startZAPFirst);
		}
		
		/*
		 * ======================================================= |WAIT FOR SUCCESSFUL CONNEXIONd| =======================================================
		 */
		
		//ici le proxy est égal à null car on applique une configuration générale où tout appel réseau provennat de la VM passe par le proxy 
		HttpUtilities.waitForSuccessfulConnectionToZap(null,defaultProtocol, zapProxyDefaultHost, zapProxyPort,zapProxyDefaultTimeoutInSec, listener);
 

		boolean res;
		try {
			res = build.getWorkspace().act(new ZAProxyCallable(zaproxy, listener));
		} catch (Exception e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
			return false;
		}
		return res;

	}

	/**
	 * Descriptor for {@link ZAProxyBuilder}. Used as a singleton. The class is
	 * marked as public so that it can be accessed from views.
	 *
	 * <p>
	 * See
	 * <tt>src/main/resources/fr/hackthem/zaproxyplugin/ZAProxyBuilder/*.jelly</tt>
	 * for the actual HTML fragment for the configuration screen.
	 */
	@Extension
	public static final ZAProxyBuilderDescriptorImpl DESCRIPTOR = new ZAProxyBuilderDescriptorImpl();

	// This indicates to Jenkins this is an implementation of an extension
	// point.
	public static final class ZAProxyBuilderDescriptorImpl extends BuildStepDescriptor<Builder>
			implements Serializable {
		/**
		 * 
		 */
		private static final long serialVersionUID = 678902562211873984L;
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

		private boolean startZAPFirst;

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
		
		
		

		/**
		 * In order to load the persisted global configuration, you have to call
		 * load() in the constructor.
		 */
		public ZAProxyBuilderDescriptorImpl() {
			load();
		}

		@Override
		public boolean isApplicable(Class<? extends AbstractProject> aClass) {
			// Indicates that this builder can be used with all kinds of project
			// types
			return true;
		}

		/**
		 * This human readable name is used in the configuration screen.
		 */
		@Override
		public String getDisplayName() {
			return "Exécuter ZAProxy";
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
			zapDefaultSSHPort = formData.getInt("zapDefaultSSHPort");
			zapDefaultSSHUser = formData.getString("zapDefaultSSHUser");
			zapDefaultSSHPassword = formData.getString("zapDefaultSSHPassword");
			zapProxyDefaultTimeoutSSHInSec = formData.getInt("zapProxyDefaultTimeoutSSHInSec");
			stopZAPAtEnd = formData.getBoolean("stopZAPAtEnd");
			authorizedURLs = formData.getString("authorizedURLs");			
			spiderURL=formData.getBoolean("spiderURL");			
			ajaxSpiderURL=formData.getBoolean("ajaxSpiderURL");
			scanURL=formData.getBoolean("scanURL");

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
		 * @return the startZAPFirst
		 */
		public boolean isStartZAPFirst() {
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

		public FormValidation doTestZAPConnection(@QueryParameter("defaultProtocol") final String protocol,

				@QueryParameter("useWebProxy") final boolean useWebProxy,
				@QueryParameter("webProxyHost") final String webProxyHost,
				@QueryParameter("webProxyPort") final int webProxyPort,
				@QueryParameter("webProxyUser") final String webProxyUser,
				@QueryParameter("webProxyPassword") final String webProxyPassword,
				
				@QueryParameter("zapDefaultDirectory") final String zapProxyDirectory,
				@QueryParameter("zapProxyDefaultHost") final String zapProxyHost,			
				@QueryParameter("zapProxyDefaultApiKey") final String zapProxyKey,
				@QueryParameter("zapProxyDefaultTimeoutInSec") final int timeoutInSec,
				
				@QueryParameter("zapDefaultSSHPort") final int zapSSHPort,
				@QueryParameter("zapDefaultSSHUser") final String zapSSHUser,
				@QueryParameter("zapDefaultSSHPassword") final String zapSSHPassword,
				@QueryParameter("zapProxyDefaultTimeoutSSHInSec") final int timeoutSSHInSec


		) {
			
			/*
			 * ======================================================= | USE WEB PROXY | =======================================================
			 */
			Proxy proxy = null;
			if (useWebProxy) {
				System.out.println("Using Web Proxy");
				Authenticator.setDefault(new ProxyAuthenticator(webProxyUser, webProxyPassword));
				// cet appel permet de ne pas généraliser le passage par le
				// proxy à toutes les appels issus de la même JVM
				proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(webProxyHost, webProxyPort));
			}
			else {
				System.out.println("Skip Using Web Proxy");
			}
			
				/*
				 * ======================================================= | CHOOSE A FREE PORT  | =======================================================
				 */
				
				
				int zapProxyPort = HttpUtilities.getPortNumber();
				
				while(HttpUtilities.portIsToken(proxy, protocol, zapProxyHost, zapProxyPort, timeoutInSec)){
					
					zapProxyPort = HttpUtilities.getPortNumber();
					
				}
 
				
				//final String linuxCommand = "Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh " + zapProxyDirectory+ "zap.sh -daemon -port " + zapProxyPort;
				final String linuxCommand = "sh " + zapProxyDirectory+ "zap.sh -daemon -port " + zapProxyPort;
				final String WindowsCommand = zapProxyDirectory + "zap.bat -daemon -port " + zapProxyPort;

				/*
				 * ======================================================= | start ZAP | =======================================================
				 */
	
				System.out.println("connexion SSH : START");
				SSHConnexion.execCommand(zapProxyHost, zapSSHPort, zapSSHUser, zapSSHPassword,HttpUtilities.getMilliseconds(timeoutSSHInSec),linuxCommand );
				System.out.println("connexion SSH : END");
	 
			 	
				
				
			HttpUtilities.waitForSuccessfulConnectionToZap(proxy,protocol, zapProxyHost, zapProxyPort,timeoutInSec);
				 
				
				
				
				
				
				/*
				 * ======================================================= | test connection | =======================================================
				 */
 

			int responseCode = 0;
			try {

				URL url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);

				HttpURLConnection conn;
				
				if(proxy == null){
					conn = (HttpURLConnection) url.openConnection();
				}
				else {
					
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
						response = (ApiResponseElement) CustomZapClientApi.sendRequest(protocol, zapProxyHost,
								zapProxyPort, "xml", "pscan", "action", "enableAllScanners", map, proxy, timeoutInSec);
					} catch (IOException e) {
						return FormValidation.error("Invalid or missing API key");
					}

					// si la clé est correcte on affiche la version de ZAP
					// installée
					response = (ApiResponseElement) CustomZapClientApi.sendRequest(protocol, zapProxyHost, zapProxyPort,
							"xml", "core", "view", "version", null, proxy, timeoutInSec);

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
			
			finally{
				
				/*
				 * ======================================================= | Stop ZAP | =======================================================
				 */	
			 
				Map<String, String> map = null;
				map = new HashMap<String, String>();
				map.put("apikey", zapProxyKey);
				try {
					 
					CustomZapClientApi.sendRequest(protocol, zapProxyHost,zapProxyPort, "xml", "core", "action", "shutdown", map, proxy, timeoutInSec);
					
				} catch (IOException | ParserConfigurationException | SAXException | ClientApiException e) {
					 
					e.printStackTrace();
					return FormValidation.error(e.getMessage() );
				}
				 
			}

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
				SSHConnexion.testSSH(zapProxyHost, zapSSHPort, zapSSHUser, zapSSHPassword,HttpUtilities.getMilliseconds(timeoutSSHInSec));
			} catch (JSchException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return FormValidation
						.error(e.getMessage() + " : Vérifier le login et le mot de passe de connextion SSH ! ");
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return FormValidation
						.error(e.getMessage() + " : Vérifier l'adresse du serveur SSH et le numéro de port !");
			}

			return FormValidation.okWithMarkup("<br><b><font color=\"green\">Connection réussie !</font></b><br>");
		}
		

	}

	/**
	 * Used to execute ZAP remotely.
	 * 
	 * @author ludovic.roucoux
	 *
	 */
	private static class ZAProxyCallable implements FileCallable<Boolean> {

		/**
		 * 
		 */
		private static final long serialVersionUID = -650973012616753534L;
		private ZAProxy zaproxy;
		private BuildListener listener;

		public ZAProxyCallable(ZAProxy zaproxy, BuildListener listener) {
			this.zaproxy = zaproxy;
			this.listener = listener;
		}

		@Override
		public Boolean invoke(File f, VirtualChannel channel) {
			return zaproxy.executeZAP(new FilePath(f), listener);
		}

		@Override
		public void checkRoles(RoleChecker checker) throws SecurityException {
			// Nothing to do
		}
	}
}
