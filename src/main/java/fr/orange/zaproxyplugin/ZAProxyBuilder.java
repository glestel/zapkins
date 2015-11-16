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

package fr.orange.zaproxyplugin;

import hudson.Extension;
import hudson.FilePath;
import hudson.FilePath.FileCallable;
import hudson.Launcher;
import hudson.Launcher.LocalLauncher;
import hudson.Launcher.RemoteLauncher;
import hudson.slaves.SlaveComputer;
import hudson.model.BuildListener;
import hudson.model.Node;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.remoting.VirtualChannel;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import fr.orange.zaproxyplugin.CustomZapClientApi;
import fr.orange.zaproxyplugin.ZAProxy;
import fr.orange.zaproxyplugin.utilities.HttpUtilities;
import fr.orange.zaproxyplugin.utilities.ProxyAuthenticator;
import fr.orange.zaproxyplugin.utilities.SSHConnexion;
import fr.orange.zaproxyplugin.utilities.SecurityTools;
import net.sf.json.JSONObject;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.tools.ant.BuildException;
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
import java.net.SocketTimeoutException;
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
 * @author abdellah.azougarh@gmail.com
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

//	/**
//	 * @param listener
//	 *            the listener to set
//	 */
//	public void setListener(BuildListener listener) {
//		this.listener = listener;
//	}

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
		//int zapProxyDefaultPort = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultPort();
		String zapProxyDefaultApiKey = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultApiKey();

		int zapDefaultSSHPort = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPort();
		String zapDefaultSSHUser = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHUser();
		String zapDefaultSSHPassword = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPassword();

		boolean useWebProxy = ZAProxyBuilder.DESCRIPTOR.isUseWebProxy();
		boolean stopZAPAtEnd = ZAProxyBuilder.DESCRIPTOR.isStopZAPAtEnd();
		boolean startZAPFirst = ZAProxyBuilder.DESCRIPTOR.isStartZAPFirst();

		String webProxyHost = ZAProxyBuilder.DESCRIPTOR.getWebProxyHost();
		int webProxyPort = ZAProxyBuilder.DESCRIPTOR.getWebProxyPort();
		String webProxyUser = ZAProxyBuilder.DESCRIPTOR.getWebProxyUser();
		String webProxyPassword = ZAProxyBuilder.DESCRIPTOR.getWebProxyPassword();

		String zapDefaultDirectory = ZAProxyBuilder.DESCRIPTOR.getZapDefaultDirectory();

		String authorizedURLs = ZAProxyBuilder.DESCRIPTOR.getAuthorizedURLs();
		
		int zapProxyPort = 0;
			
		

		/*
		 * ======================================================= | USE WEB PROXY | =======================================================
		 */
		if (useWebProxy) {
			// Ici on généralise l'utilisation du proxy web à tous les appels
			// passés via la JVM
			CustomZapClientApi.setWebProxyDetails(webProxyHost, webProxyPort, webProxyUser, webProxyPassword);
		} else {
			listener.getLogger().println("Skip using web proxy");
		}
		
			
		

		if (startZAPFirst) {
			
			
			
			/*
			 * ======================================================= | CHOOSE A FREE PORT  | =======================================================
			 */
			
			
			zapProxyPort = HttpUtilities.getPortNumber();
			
			while(HttpUtilities.portIsToken(null, defaultProtocol, zapProxyDefaultHost, zapProxyPort, zapProxyDefaultTimeoutInSec, listener)){
				
				zapProxyPort = HttpUtilities.getPortNumber();
				
			}
			
			//zapProxyDefaultPort=zapProxyPort;	
			zaproxy.setZapProxyPort(zapProxyPort);
			
			
			
			listener.getLogger().println("------- START Prebuild -------");

			listener.getLogger().println("Perform ZAProxy");
			
			final String linuxCommand = "Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh " + zapDefaultDirectory
					+ "zap.sh -daemon -port " + zapProxyPort;
			final String WindowsCommand = zapDefaultDirectory + "zap.bat -daemon -port " + zapProxyPort;

			/*
			 * ======================================================= | start ZAP | =======================================================
			 */

			listener.getLogger().println("Starting ZAP remotely (SSH)");
//			listener.getLogger().println("SSH PORT : " + zapDefaultSSHPort);
//			listener.getLogger().println("SSH USER : " + zapDefaultSSHUser);
//			listener.getLogger().println("SSH PASSWORD : " + zapDefaultSSHPassword);
//			listener.getLogger().println("COMMAND : " + linuxCommand);
//			listener.getLogger().println("LISTENER : " + listener);
//			listener.getLogger().println("ZAP DIRECTORY : " + zapDefaultDirectory);
 
			SSHConnexion.execCommand(zapProxyDefaultHost, zapDefaultSSHPort, zapDefaultSSHUser, zapDefaultSSHPassword,linuxCommand, listener);
 
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

//	/**
//	 * Wait for ZAProxy initialization, so it's ready to use at the end of this
//	 * method (otherwise, catch exception). This method is launched on the
//	 * remote machine (if there is one)
//	 * 
//	 * @param timeout
//	 *            the time in sec to try to connect at zap proxy.
//	 * @param listener
//	 *            the listener to display log during the job execution in
//	 *            jenkins
//	 * @see <a href=
//	 *      "https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960">
//	 *      https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960
//	 *      </a>
//	 */
//	private void waitForSuccessfulConnectionToZap(String protocol, String zapProxyHost, int zapProxyPort, int timeout,
//			BuildListener listener) {
//
//		int timeoutInMs = getMilliseconds(timeout);
//		int connectionTimeoutInMs = timeoutInMs;
//		int pollingIntervalInMs = getMilliseconds(1);
//		boolean connectionSuccessful = false;
//		long startTime = System.currentTimeMillis();
//
//		URL url;
//
//		do {
//			try {
//				listener.getLogger().println(protocol + "://" + zapProxyHost + ":" + zapProxyPort);
//				url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);
//
//				connectionSuccessful = checkURL(url, connectionTimeoutInMs, listener);
//
//			} catch (SocketTimeoutException ignore) {
//
//				throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
//
//			} catch (IOException ignore) {
//				// and keep trying but wait some time first...
//				try {
//					Thread.sleep(pollingIntervalInMs);
//				} catch (InterruptedException e) {
//
//					throw new BuildException("The task was interrupted while sleeping between connection polling.", e);
//				}
//
//				long ellapsedTime = System.currentTimeMillis() - startTime;
//				if (ellapsedTime >= timeoutInMs) {
//
//					throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
//				}
//				connectionTimeoutInMs = (int) (timeoutInMs - ellapsedTime);
//			}
//		} while (!connectionSuccessful);
//	}
//
//	
//
//	/**
//	 * Converts seconds in milliseconds.
//	 * 
//	 * @param seconds
//	 *            the time in second to convert
//	 * @return the time in milliseconds
//	 */
//	private static int getMilliseconds(int seconds) {
//		return seconds * MILLISECONDS_IN_SECOND;
//	}
//
//	private boolean checkURL(URL url, int connectionTimeoutInMs, BuildListener listener) throws IOException {
//
//		/******************************************/
//		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
//		conn.setRequestMethod("GET");
//		conn.setConnectTimeout(connectionTimeoutInMs);
//		System.out.println(String.format("Fetching %s ...", url));
//		listener.getLogger().println(String.format("Fetching %s ...", url));
//		// try {
//		int responseCode = conn.getResponseCode();
//		if (responseCode == 200) {
//			System.out.println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
//			listener.getLogger()
//					.println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
//			return true;
//		} else {
//			System.out.println(String.format("Site is up, but returns non-ok status = %d", responseCode));
//			listener.getLogger().println(String.format("Site is up, but returns non-ok status = %d", responseCode));
//			return false;
//		}
//	}
// 

	/**
	 * Descriptor for {@link ZAProxyBuilder}. Used as a singleton. The class is
	 * marked as public so that it can be accessed from views.
	 *
	 * <p>
	 * See
	 * <tt>src/main/resources/fr/novia/zaproxyplugin/ZAProxyBuilder/*.jelly</tt>
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
		//private int zapProxyDefaultPort;
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
			//zapProxyDefaultPort = formData.getInt("zapProxyDefaultPort");
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

//		public int getZapProxyDefaultPort() {
//			return zapProxyDefaultPort;
//		}

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

				Authenticator.setDefault(new ProxyAuthenticator(webProxyUser, webProxyPassword));
				// cet appel permet de ne pas généraliser le passage par le
				// proxy à toutes les appels issus de la même JVM
				proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(webProxyHost, webProxyPort));
			}
			
			
				/*
				 * ======================================================= | CHOOSE A FREE PORT  | =======================================================
				 */
				
				
				int zapProxyPort = HttpUtilities.getPortNumber();
				
				while(HttpUtilities.portIsToken(proxy, protocol, zapProxyHost, zapProxyPort, timeoutInSec)){
					
					zapProxyPort = HttpUtilities.getPortNumber();
					
				}
 
				
				final String linuxCommand = "Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh " + zapProxyDirectory+ "zap.sh -daemon -port " + zapProxyPort;
				final String WindowsCommand = zapProxyDirectory + "zap.bat -daemon -port " + zapProxyPort;

				/*
				 * ======================================================= | start ZAP | =======================================================
				 */

				System.out.println("connexion SSH : START");
				SSHConnexion.execCommand(zapProxyHost, zapSSHPort, zapSSHUser, zapSSHPassword,linuxCommand );
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
					// String apikey="p5vocslricjcadf8333rnkv0e6";
					if (zapProxyKey != null) {
						map.put("apikey", zapProxyKey);
					}
					// http://10.107.2.102:8080/JSON/pscan/action/enableAllScanners/?zapapiformat=JSON&apikey=wbxvnvxcw%2Cwc
					// http://10.107.2.102:8080/XML/core/view/version/?zapapiformat=XML

					ApiResponseElement response;
					// si la clé n'est pas correcte, une exception est lancée

					try {
						response = (ApiResponseElement) CustomZapClientApi.sendRequest(protocol, zapProxyHost,
								zapProxyPort, "xml", "pscan", "action", "enableAllScanners", map, proxy, timeoutInSec);
					} catch (IOException e) {
						return FormValidation.error("Invalid or missing API key");// +s.toString());
					}

					// si la clé est correcte on affiche la version de ZAP
					// installée
					response = (ApiResponseElement) CustomZapClientApi.sendRequest(protocol, zapProxyHost, zapProxyPort,
							"xml", "core", "view", "version", null, proxy, timeoutInSec);

					return FormValidation.okWithMarkup("<br><b><FONT COLOR=\"green\">Success : 200\nSite is up" + "<br>"
							+ "ZAP Proxy(" + response.getName() + ")=" + response.getValue() + "</FONT></b></br>"); // +s.toString());

				} else {
					System.out.println(String.format("<br>Site is up, but returns non-ok status = %d", responseCode));
					return FormValidation.warning("Site is up, but returns non-ok status = " + responseCode);// +s.toString());
				}

			} catch (MalformedURLException e) {

				e.printStackTrace();
				return FormValidation.error(e.getMessage() + "\nHTTP Response code=" + responseCode);// +s.toString());

			} catch (IOException e) {

				e.printStackTrace();
				return FormValidation.error(e.getMessage());// +s.toString());
			} catch (ParserConfigurationException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return FormValidation.error(e.getMessage() + "\nHTTP Response code=" + responseCode);// +s.toString());
			} catch (SAXException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return FormValidation.error(e.getMessage() + "\nHTTP Response code=" + responseCode);// +s.toString());
			} catch (ClientApiException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
				return FormValidation.error(e.getMessage() + "\nHTTP Response code=" + responseCode);// +s.toString());
			}
			
			finally{
				
				/*
				 * ======================================================= | Stop ZAP | =======================================================
				 */	
			 
				Map<String, String> map = null;
				map = new HashMap<String, String>();
				map.put("apikey", zapProxyKey);
				try {
					 
					ApiResponseElement set = (ApiResponseElement) CustomZapClientApi.sendRequest(protocol, zapProxyHost,
							zapProxyPort, "xml", "core", "action", "shutdown", map, proxy, timeoutInSec);
				} catch (IOException | ParserConfigurationException | SAXException | ClientApiException e) {
					 
					e.printStackTrace();
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
		
//		
//		/**
//		 * Wait for ZAProxy initialization, so it's ready to use at the end of this
//		 * method (otherwise, catch exception). This method is launched on the
//		 * remote machine (if there is one)
//		 * 
//		 * @param timeout
//		 *            the time in sec to try to connect at zap proxy.
//		 * @param listener
//		 *            the listener to display log during the job execution in
//		 *            jenkins
//		 * @see <a href=
//		 *      "https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960">
//		 *      https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960
//		 *      </a>
//		 */
//		private void waitForSuccessfulConnectionToZap(Proxy proxy,String protocol, String zapProxyHost, int zapProxyPort, int timeout) {
//
//			int timeoutInMs = getMilliseconds(timeout);
//			int connectionTimeoutInMs = timeoutInMs;
//			int pollingIntervalInMs = getMilliseconds(1);
//			boolean connectionSuccessful = false;
//			long startTime = System.currentTimeMillis();
//
//			URL url;
//
//			do {
//				try {
//					 
//					url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);
//
//					connectionSuccessful = checkURL(proxy,url, connectionTimeoutInMs );
//
//				} catch (SocketTimeoutException ignore) {
//
//					throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
//
//				} catch (IOException ignore) {
//					// and keep trying but wait some time first...
//					try {
//						Thread.sleep(pollingIntervalInMs);
//					} catch (InterruptedException e) {
//
//						throw new BuildException("The task was interrupted while sleeping between connection polling.", e);
//					}
//
//					long ellapsedTime = System.currentTimeMillis() - startTime;
//					if (ellapsedTime >= timeoutInMs) {
//
//						throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
//					}
//					connectionTimeoutInMs = (int) (timeoutInMs - ellapsedTime);
//				}
//			} while (!connectionSuccessful);
//		}
//
//		 
//
//		/**
//		 * Converts seconds in milliseconds.
//		 * 
//		 * @param seconds
//		 *            the time in second to convert
//		 * @return the time in milliseconds
//		 */
//		private static int getMilliseconds(int seconds) {
//			return seconds * MILLISECONDS_IN_SECOND;
//		}
//
//		private boolean checkURL(Proxy proxy,URL url, int connectionTimeoutInMs ) throws IOException {
//
//			/******************************************/
//			HttpURLConnection conn;
//			if(proxy != null){
//			conn = (HttpURLConnection) url.openConnection(proxy);
//			}
//			else {
//				
//			conn = (HttpURLConnection) url.openConnection();	
//			}
//			conn.setRequestMethod("GET");
//			conn.setConnectTimeout(connectionTimeoutInMs);
//			System.out.println(String.format("Fetching %s ...", url));
//			 
//			// try {
//			int responseCode = conn.getResponseCode();
//			if (responseCode == 200) {
//				System.out.println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
//				 
//				return true;
//			} else {
//				System.out.println(String.format("Site is up, but returns non-ok status = %d", responseCode));
//				 
//				return false;
//			}
//		}
		
		
		
		
		

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
