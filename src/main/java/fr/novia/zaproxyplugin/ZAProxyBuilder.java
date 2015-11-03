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
import fr.novia.zaproxyplugin.utilities.ProxyAuthenticator;
import fr.novia.zaproxyplugin.utilities.SSHConnexion;
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
 * @author ludovic.roucoux
 *
 */
public class ZAProxyBuilder extends Builder {

	private static final int MILLISECONDS_IN_SECOND = 1000;

	private final String protocol;

	private final int timeoutInSec;
	
	private final int timeoutSSHInSec;

	/** The objet to start and call ZAProxy methods */
	private final ZAProxy zaproxy;

	/** Host configured when ZAProxy is used as proxy */
	private final String zapProxyHost;

	/** Port configured when ZAProxy is used as proxy */
	private final int zapProxyPort;

	/** API Key configured when ZAProxy is used as proxy */
	private final String zapProxyKey;

	/** ZAP Directory configured when ZAProxy is used as proxy */
	private final String zapProxyDirectory;	
	/** proxyWeb host */
	private final String webProxyHost;
	/** proxyWeb port */
	private final int webProxyPort;
	/** proxyWeb username */
	private final String webProxyUser;
	/** proxyWeb password */
	private final String webProxyPassword;

	/** use or not a proxyWeb */
	private final boolean useWebProxy;

	/** start ZAP remotely */
	private final boolean startZAPFirst;

	/** stop ZAP At the end of scan */
	private final boolean stopZAPAtEnd;
	
	/************ SSH ****************/
	/** SSH PORT configured when ZAProxy is used as proxy */
	private final int zapSSHPort;

	/** SSH USER configured when ZAProxy is used as proxy */
	private final String zapSSHUser;

	/** SSH PASSWORD configured when ZAProxy is used as proxy */
	private final String zapSSHPassword;
	
	
	//On ne peut pas rendre ce champs final, car on ne peut l'initialiser à travers le constructeur
	private BuildListener listener;




	// Fields in fr/novia/zaproxyplugin/ZAProxyBuilder/config.jelly must match
	// the parameter names in the "DataBoundConstructor"
	@DataBoundConstructor
	public ZAProxyBuilder(int timeoutSSHInSec,  int timeoutInSec, String protocol, ZAProxy zaproxy, String zapProxyHost, int zapProxyPort,
			int zapSSHPort, String zapSSHUser, String zapSSHPassword, boolean startZAPFirst, boolean stopZAPAtEnd,
			boolean useWebProxy, String zapProxyDirectory, String zapProxyKey, String webProxyHost, int webProxyPort,
			String webProxyUser, String webProxyPassword) {
		
		
		super();
		this.zaproxy = zaproxy;
		
		this.startZAPFirst = startZAPFirst;
		this.stopZAPAtEnd = stopZAPAtEnd;

		
		/***************** TIME OUT *******************************/
		this.timeoutSSHInSec=timeoutSSHInSec;
		this.timeoutInSec = timeoutInSec;
		this.zaproxy.setTimeoutInSec(timeoutInSec);
		this.zaproxy.setTimeoutSSHInSec(timeoutSSHInSec);
		
        /***************** ZAP PROXY *******************************/
		this.protocol = protocol;		
		this.zapProxyHost = zapProxyHost;
		this.zapProxyPort = zapProxyPort;
		this.zapProxyKey = zapProxyKey;
		this.zapProxyDirectory = zapProxyDirectory;
		this.zaproxy.setZapProxyHost(zapProxyHost);
		this.zaproxy.setZapProxyPort(zapProxyPort);
		this.zaproxy.setZapProxyApiKey(zapProxyKey);
		this.zaproxy.setZapProxyDirectory(zapProxyDirectory);
		
		/****************** WEB PROXY ******************************/
		this.useWebProxy = useWebProxy;
		this.webProxyHost = webProxyHost;
		this.webProxyPort = webProxyPort;
		this.webProxyUser = webProxyUser;
		this.webProxyPassword = webProxyPassword;		 
		this.zaproxy.setWebProxyHost(webProxyHost);
		this.zaproxy.setWebProxyPort(webProxyPort);
		this.zaproxy.setWebProxyUser(webProxyUser);
		this.zaproxy.setWebProxyPassword(webProxyPassword);
		
		/****************** SSH SERVICE ******************************/
		this.zapSSHPort = zapSSHPort;
		this.zapSSHUser = zapSSHUser;
		this.zapSSHPassword = zapSSHPassword;
		this.zaproxy.setZapSSHPort(zapSSHPort);
		this.zaproxy.setZapSSHUser(zapSSHUser);
		this.zaproxy.setZapSSHPassword(zapSSHPassword);
		/************************************************/


		 



	}

	/*
	 * Getters allows to access member via UI (config.jelly)
	 */

	public int getTimeoutInSec() {
		return timeoutInSec;
	}

	/**
	 * @return the timeoutSSHInSec
	 */
	public int getTimeoutSSHInSec() {
		return timeoutSSHInSec;
	}

	/**
	 * @return the useWebProxy
	 */
	public boolean isUseWebProxy() {
		return useWebProxy;
	}

	/**
	 * @return the startZAP
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

	public ZAProxy getZaproxy() {
		return zaproxy;
	}

	public String getZapProxyHost() {
		return zapProxyHost;
	}

	public int getZapProxyPort() {
		return zapProxyPort;
	}

	public String getZapProxyKey() {
		return zapProxyKey;
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
	 * @return the zapProxyDirectory
	 */
	public String getZapProxyDirectory() {
		return zapProxyDirectory;
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
	 * @return the pROTOCOL
	 */
	public String getProtocol() {
		return protocol;
	}	

	/**
	 * @return the listener
	 */
	public BuildListener getListener() {
		return listener;
	}

	/**
	 * @param listener
	 *            the listener to set
	 */
	public void setListener(BuildListener listener) {
		this.listener = listener;
	}

	// Overridden for better type safety.
	// If your plugin doesn't really define any property on Descriptor,
	// you don't have to do this.
	@Override
	public ZAProxyBuilderDescriptorImpl getDescriptor() {
		return (ZAProxyBuilderDescriptorImpl) super.getDescriptor();
	}



//	/**
//	 * @param zapSSHPort
//	 *            the zapSSHPort to set
//	 */
//	public void setZapSSHPort(int zapSSHPort) {
//		this.zapSSHPort = zapSSHPort;
//	}
//
//	/**
//	 * @param zapSSHUser
//	 *            the zapSSHUser to set
//	 */
//	public void setZapSSHUser(String zapSSHUser) {
//		this.zapSSHUser = zapSSHUser;
//	}
//
//	/**
//	 * @param zapSSHPassword
//	 *            the zapSSHPassword to set
//	 */
//	public void setZapSSHPassword(String zapSSHPassword) {
//		this.zapSSHPassword = zapSSHPassword;
//	}


	// Method called before launching the build
	public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {
		
//		if(startZAPFirst) {
//			listener.getLogger().println("------- START Prebuild -------");
//			
//			try {
//				Launcher launcher = null;
//				Node node = build.getBuiltOn();
//				
//				// Create launcher according to the build's location (Master or Slave) and the build's OS
//				
//				if("".equals(node.getNodeName())) { // Build on master 
//					launcher = new LocalLauncher(listener, build.getWorkspace().getChannel());
//				} else { // Build on slave
//					boolean isUnix;
//					if( "Unix".equals(((SlaveComputer)node.toComputer()).getOSDescription()) ) {
//						isUnix = true;
//					} else {
//						isUnix = false;
//					}
//					launcher = new RemoteLauncher(listener, build.getWorkspace().getChannel(), isUnix);
//				}	
//				
//				
//				
//				
//				zaproxy.startZAP(build, listener, launcher);
//				
//				
//				
//				
//				
//				
//				
//				
//				
//				
//				
//				
//				
//				
//				
//			} catch (Exception e) {
//				e.printStackTrace();
//				listener.error(ExceptionUtils.getStackTrace(e));
//				return false;
//			}
//			listener.getLogger().println("------- END Prebuild -------");
//		}
//		return true;
		 
		if (startZAPFirst) {
			listener.getLogger().println("------- START Prebuild -------");

			listener.getLogger().println("Perform ZAProxy");
			final String linuxCommand = "sh " +this.getZapProxyDirectory() + "zap.sh -daemon";
			final String WindowsCommand = this.getZapProxyDirectory() + "zap.bat -daemon";
			 
			
			/*
			 * ======================================================= | start
			 * ZAP | =======================================================
			 */

			listener.getLogger().println("Starting ZAP remotely (SSH)");
			listener.getLogger().println("SSH PORT : " + this.getZapSSHPort());
			listener.getLogger().println("SSH USER : " + this.getZapSSHUser());
			listener.getLogger().println("ZAP DIRECTORY : " + this.getZapProxyDirectory());

			Thread queryThread = new Thread() {
				public void run() {
					SSHConnexion.execCommand(getZapProxyHost(), getZapSSHPort(), getZapSSHUser(), getZapSSHPassword(),linuxCommand, getListener());
				}
			};
			queryThread.start();


			listener.getLogger().println("------- END Prebuild -------");
		}

		else {
			listener.getLogger().println("Skip starting ZAP remotely");
			listener.getLogger().println("startZAPFirst : " + startZAPFirst);
		}
		return true;
	}

	// Methode appelée pendant le build, c'est ici que zap est lancé
	@Override
	public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {

		/*
		 * ======================================================= | USE WEB
		 * PROXY | =======================================================
		 */
		if (useWebProxy) {
			//Ici on généralise l'utilisation du proxy web à tous les appels passés via la JVM
			CustomZapClientApi.setWebProxyDetails(webProxyHost, webProxyPort, webProxyUser, webProxyPassword);
		} else {
			listener.getLogger().println("Skip using web proxy");
		}

		this.waitForSuccessfulConnectionToZap(protocol, zapProxyHost, zapProxyPort, timeoutInSec, listener);

//		try {
//			//à voir à quoi il sert cet appel
//			zaproxy.startZAP(build, listener, launcher);
//		} catch (Exception e) {
//			e.printStackTrace();
//			listener.error(ExceptionUtils.getStackTrace(e));
//			return false;
//		}

		boolean res;
		try {
			res = build.getWorkspace().act(new ZAProxyCallable(this.zaproxy, listener));
		} catch (Exception e) {
			e.printStackTrace();
			listener.error(ExceptionUtils.getStackTrace(e));
			return false;
		}
		return res;

	}

	/**
	 * Wait for ZAProxy initialization, so it's ready to use at the end of this
	 * method (otherwise, catch exception). This method is launched on the
	 * remote machine (if there is one)
	 * 
	 * @param timeout
	 *            the time in sec to try to connect at zap proxy.
	 * @param listener
	 *            the listener to display log during the job execution in
	 *            jenkins
	 * @see <a href=
	 *      "https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960">
	 *      https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960
	 *      </a>
	 */
	private void waitForSuccessfulConnectionToZap(String protocol, String zapProxyHost, int zapProxyPort, int timeout,
			BuildListener listener) {

		int timeoutInMs = getMilliseconds(timeout);
		int connectionTimeoutInMs = timeoutInMs;
		int pollingIntervalInMs = getMilliseconds(1);
		boolean connectionSuccessful = false;
		long startTime = System.currentTimeMillis();

		URL url;

		do {
			try {
				listener.getLogger().println(protocol + "://" + zapProxyHost + ":" + zapProxyPort);
				url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);

				connectionSuccessful = checkURL(url, connectionTimeoutInMs, listener);

			} catch (SocketTimeoutException ignore) {

				throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");

			} catch (IOException ignore) {
				// and keep trying but wait some time first...
				try {
					Thread.sleep(pollingIntervalInMs);
				} catch (InterruptedException e) {

					throw new BuildException("The task was interrupted while sleeping between connection polling.", e);
				}

				long ellapsedTime = System.currentTimeMillis() - startTime;
				if (ellapsedTime >= timeoutInMs) {

					throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
				}
				connectionTimeoutInMs = (int) (timeoutInMs - ellapsedTime);
			}
		} while (!connectionSuccessful);
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
//	 * @throws IOException
//	 * @see <a href=
//	 *      "https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960">
//	 *      https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960
//	 *      </a>
//	 */
//	private static boolean checkConnectionToZap(String PROTOCOL, String zapProxyHost, int zapProxyPort, int timeout)
//			throws IOException {
//
//		int timeoutInMs = getMilliseconds(timeout);
//		int connectionTimeoutInMs = timeoutInMs;
//		int pollingIntervalInMs = getMilliseconds(1);
//		boolean connectionSuccessful = false;
//		long startTime = System.currentTimeMillis();
//
//		URL url;
//
//		// try {
//		url = new URL(PROTOCOL + "://" + zapProxyHost + ":" + zapProxyPort);
//		connectionSuccessful = checkURL(url, connectionTimeoutInMs);
//		return connectionSuccessful;
//
//		// } catch (SocketTimeoutException ignore) {
//		//
//		// throw new BuildException("Unable to connect to ZAP's proxy after " +
//		// timeout + " seconds.");
//		//
//		// } catch (IOException ignore) {
//		// // and keep trying but wait some time first...
//		// try {
//		// Thread.sleep(pollingIntervalInMs);
//		// } catch (InterruptedException e) {
//		//
//		// throw new BuildException("The task was interrupted while sleeping
//		// between connection polling.", e);
//		// }
//		//
//		// long ellapsedTime = System.currentTimeMillis() - startTime;
//		// if (ellapsedTime >= timeoutInMs) {
//		//
//		// throw new BuildException("Unable to connect to ZAP's proxy after " +
//		// timeout + " seconds.");
//		// }
//		// connectionTimeoutInMs = (int) (timeoutInMs - ellapsedTime);
//		// }
//
//	}

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

	private boolean checkURL(URL url, int connectionTimeoutInMs, BuildListener listener) throws IOException {

		/******************************************/
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("GET");
		conn.setConnectTimeout(connectionTimeoutInMs);
		System.out.println(String.format("Fetching %s ...", url));
		listener.getLogger().println(String.format("Fetching %s ...", url));
		// try {
		int responseCode = conn.getResponseCode();
		if (responseCode == 200) {
			System.out.println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
			listener.getLogger()
					.println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
			return true;
		} else {
			System.out.println(String.format("Site is up, but returns non-ok status = %d", responseCode));
			listener.getLogger().println(String.format("Site is up, but returns non-ok status = %d", responseCode));
			return false;
		}
	}

//	private static boolean checkURL(URL url, int connectionTimeoutInMs) throws IOException {
//
//		/******************************************/
//		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
//		conn.setRequestMethod("GET");
//		conn.setConnectTimeout(connectionTimeoutInMs);
//		System.out.println(String.format("Fetching %s ...", url));
//		// listener.getLogger().println(String.format("Fetching %s ...", url));
//		try {
//		int responseCode = conn.getResponseCode();
//		if (responseCode == 200) {
//			System.out.println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
//			// listener.getLogger().println(String.format("Site is up, content
//			// length = %s", conn.getHeaderField("content-length")));
//			return true;
//		} else {
//			System.out.println(String.format("Site is up, but returns non-ok status = %d", responseCode));
//			// listener.getLogger().println(String.format("Site is up, but
//			// returns non-ok status = %d", responseCode));
//			return false;
//		}
//		 } catch (java.net.UnknownHostException e) {
//		     System.out.println("Site is down");
//		//listener.getLogger().println("Site is down");
//		 return false;
//		 }
//	}

	/**
	 * Descriptor for {@link ZAProxyBuilder}. Used as a singleton. The class is
	 * marked as public so that it can be accessed from views.
	 *
	 * <p>
	 * See
	 * <tt>src/main/resources/fr/novia/zaproxyplugin/ZAProxyBuilder/*.jelly</tt>
	 * for the actual HTML fragment for the configuration screen.
	 */
	@Extension // This indicates to Jenkins this is an implementation of an
				// extension point.
	public static final class ZAProxyBuilderDescriptorImpl extends BuildStepDescriptor<Builder>implements Serializable {
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
		private int zapProxyDefaultTimeoutInSec;
		private String zapProxyDefaultHost;
		private int zapProxyDefaultPort;
		/** API Key configured when ZAProxy is used as proxy */
		private String zapProxyDefaultApiKey;

		/** ZAP default Directory configured when ZAProxy is used as proxy */
		private String zapDefaultDirectory;

		/** ZAP default SSH port configured when ZAProxy is used as proxy */
		private int zapDefaultSSHPort;

		/** ZAP default SSH port configured when ZAProxy is used as proxy */
		private String zapDefaultSSHUser;

		/** ZAP default SSH port configured when ZAProxy is used as proxy */
		private String zapDefaultSSHPassword;
		
		
		
		private int zapProxyDefaultTimeoutSSHInSec;

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
			zapProxyDefaultHost = formData.getString("zapProxyDefaultHost");
			zapProxyDefaultPort = formData.getInt("zapProxyDefaultPort");
			zapProxyDefaultApiKey = formData.getString("zapProxyDefaultApiKey");
			zapDefaultDirectory = formData.getString("zapDefaultDirectory");
			zapProxyDefaultTimeoutInSec = formData.getInt("zapProxyDefaultTimeoutInSec");
			
			zapProxyDefaultTimeoutSSHInSec= formData.getInt("zapProxyDefaultTimeoutSSHInSec");
			zapDefaultSSHPort = formData.getInt("zapDefaultSSHPort");
			zapDefaultSSHUser = formData.getString("zapDefaultSSHUser");
			zapDefaultSSHPassword = formData.getString("zapDefaultSSHPassword");

			// ^Can also use req.bindJSON(this, formData);
			// (easier when there are many fields; need set* methods for this,
			// like setUseFrench)
			save();
			return super.configure(req, formData);
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

		public int getZapProxyDefaultPort() {
			return zapProxyDefaultPort;
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

		public FormValidation doTestZAPConnection(@QueryParameter("protocol") final String protocol,
				@QueryParameter("useWebProxy") final boolean useWebProxy,
				@QueryParameter("webProxyHost") final String webProxyHost,
				@QueryParameter("webProxyPort") final int webProxyPort,
				@QueryParameter("webProxyUser") final String webProxyUser,
				@QueryParameter("webProxyPassword") final String webProxyPassword,
				@QueryParameter("zapProxyHost") final String zapProxyHost,
				@QueryParameter("zapProxyPort") final int zapProxyPort,
				@QueryParameter("zapProxyKey") final String zapProxyKey,
				@QueryParameter("timeoutInSec") final int timeoutInSec

		) {

			/******************************************/
			// String s = "";
			//
			// s += "\n--------------------------------------------------\n";
			// s += "useWebProxy ["+useWebProxy+"]\n";
			// s += "webProxyHost ["+webProxyHost+"]\n";
			// s += "webProxyPort ["+webProxyPort+"]\n";
			// s += "webProxyUser ["+webProxyUser+"]\n";
			// s += "webProxyPassword ["+webProxyPassword+"]\n";
			//
			//
			// s += "zapProxyHost ["+zapProxyHost+"]\n";
			// s += "zapProxyPort ["+zapProxyPort+"]\n";
			// s += "zapProxyKey ["+zapProxyKey+"]\n";

			int responseCode = 0;
			try {

				URL url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);

				HttpURLConnection conn;

				/*
				 * ======================================================= | USE
				 * WEB PROXY |
				 * =======================================================
				 */
				Proxy proxy = null;
				if (useWebProxy) {
					Authenticator.setDefault(new ProxyAuthenticator(webProxyUser, webProxyPassword));
					proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(webProxyHost, webProxyPort));

					conn = (HttpURLConnection) url.openConnection(proxy);

				}

				else {

					conn = (HttpURLConnection) url.openConnection();
				}

				/*
				 * *************************************************************
				 * *******************************
				 */

				conn.setRequestMethod("GET");
				conn.setConnectTimeout(getMilliseconds(timeoutInSec));
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

		}

		public FormValidation doTestSSHConnection(

				@QueryParameter("zapProxyHost") final String zapProxyHost, 
				@QueryParameter("zapSSHPort") final int zapSSHPort,
				@QueryParameter("zapSSHUser") final String zapSSHUser,
				@QueryParameter("zapSSHPassword") final String zapSSHPassword,
				@QueryParameter("timeoutSSHInSec") final int timeoutSSHInSec

		) {

			/******************************************/
			// String s = "";
			//
			// s += "\n--------------------------------------------------\n";
			// s += "useWebProxy ["+useWebProxy+"]\n";
			// s += "webProxyHost ["+webProxyHost+"]\n";
			// s += "webProxyPort ["+webProxyPort+"]\n";
			// s += "webProxyUser ["+webProxyUser+"]\n";
			// s += "webProxyPassword ["+webProxyPassword+"]\n";
			//
			//
			// s += "zapProxyHost ["+zapProxyHost+"]\n";
			// s += "zapProxyPort ["+zapProxyPort+"]\n";
			// s += "zapProxyKey ["+zapProxyKey+"]\n";
			/*
			 * ======================================================= | USE WEB
			 * PROXY | =======================================================
			 */

			try {
				SSHConnexion.testSSH(zapProxyHost, zapSSHPort, zapSSHUser, zapSSHPassword,getMilliseconds(timeoutSSHInSec) );
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
