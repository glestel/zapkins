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

package  fr.orange.zaproxyplugin;

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
import  fr.orange.zaproxyplugin.utilities.ProxyAuthenticator;
import  fr.orange.zaproxyplugin.utilities.SSHConnexion;
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

	private String defaultProtocol;

	private int zapProxyDefaultTimeoutInSec;

	private int zapProxyDefaultTimeoutSSHInSec;

	/** The objet to start and call ZAProxy methods */
	private final ZAProxy zaproxy;
	
	

	/** Host configured when ZAProxy is used as proxy */
	private String zapProxyDefaultHost;

	/** Port configured when ZAProxy is used as proxy */
	private int zapProxyDefaultPort;

	/** API Key configured when ZAProxy is used as proxy */
	private String zapProxyDefaultApiKey;

	/** ZAP Directory configured when ZAProxy is used as proxy */
	private String zapDefaultDirectory;
	
	
	
	
	/** proxyWeb host */
	private String webProxyHost;
	/** proxyWeb port */
	private int webProxyPort;
	/** proxyWeb username */
	private String webProxyUser;
	/** proxyWeb password */
	private String webProxyPassword;

	/** use or not a proxyWeb */
	private boolean useWebProxy;

	/** start ZAP remotely */
	private boolean startZAPFirst;

	/** stop ZAP At the end of scan */
	private boolean stopZAPAtEnd;

	/************ SSH ****************/
	/** SSH PORT configured when ZAProxy is used as proxy */
	private int zapDefaultSSHPort;

	/** SSH USER configured when ZAProxy is used as proxy */
	private String zapDefaultSSHUser;

	/** SSH PASSWORD configured when ZAProxy is used as proxy */
	private String zapDefaultSSHPassword;
	
	private String authorizedURLs;



	// On ne peut pas rendre ce champs final, car on ne peut l'initialiser à
	// travers le constructeur
	private BuildListener listener;

	// Fields in fr/novia/zaproxyplugin/ZAProxyBuilder/config.jelly must match
	// the parameter names in the "DataBoundConstructor"
	// @DataBoundConstructor
	// public ZAProxyBuilder(int timeoutSSHInSec, int timeoutInSec, String
	// protocol, ZAProxy zaproxy, String zapProxyHost, int zapProxyPort,
	// int zapSSHPort, String zapSSHUser, String zapSSHPassword, boolean
	// startZAPFirst, boolean stopZAPAtEnd,
	// boolean useWebProxy, String zapProxyDirectory, String zapProxyKey, String
	// webProxyHost, int webProxyPort,
	// String webProxyUser, String webProxyPassword) {
	//
	//
	// super();
	// this.zaproxy = zaproxy;
	//
	// this.startZAPFirst = startZAPFirst;
	// this.stopZAPAtEnd = stopZAPAtEnd;
	// this.zaproxy.setStopZAPAtEnd(stopZAPAtEnd);
	//
	//
	// /***************** TIME OUT *******************************/
	// this.timeoutSSHInSec=timeoutSSHInSec;
	// this.timeoutInSec = timeoutInSec;
	// this.zaproxy.setTimeoutInSec(timeoutInSec);
	// this.zaproxy.setTimeoutSSHInSec(timeoutSSHInSec);
	//
	// /***************** ZAP PROXY *******************************/
	// this.protocol = protocol;
	// this.zaproxy.setProtocol(protocol);
	//
	//
	// this.zapProxyHost = zapProxyHost;
	// this.zapProxyPort = zapProxyPort;
	// this.zapProxyKey = zapProxyKey;
	// this.zapProxyDirectory = zapProxyDirectory;
	// this.zaproxy.setZapProxyHost(zapProxyHost);
	// this.zaproxy.setZapProxyPort(zapProxyPort);
	// this.zaproxy.setZapProxyApiKey(zapProxyKey);
	// this.zaproxy.setZapProxyDirectory(zapProxyDirectory);
	//
	// /****************** WEB PROXY ******************************/
	// this.useWebProxy = useWebProxy;
	// this.webProxyHost = webProxyHost;
	// this.webProxyPort = webProxyPort;
	// this.webProxyUser = webProxyUser;
	// this.webProxyPassword = webProxyPassword;
	// this.zaproxy.setWebProxyHost(webProxyHost);
	// this.zaproxy.setWebProxyPort(webProxyPort);
	// this.zaproxy.setWebProxyUser(webProxyUser);
	// this.zaproxy.setWebProxyPassword(webProxyPassword);
	//
	// /****************** SSH SERVICE ******************************/
	// this.zapSSHPort = zapSSHPort;
	// this.zapSSHUser = zapSSHUser;
	// this.zapSSHPassword = zapSSHPassword;
	// this.zaproxy.setZapSSHPort(zapSSHPort);
	// this.zaproxy.setZapSSHUser(zapSSHUser);
	// this.zaproxy.setZapSSHPassword(zapSSHPassword);
	// /************************************************/
	//
	//
	//
	//
	//
	//
	// }

	@DataBoundConstructor
	public ZAProxyBuilder(  ZAProxy zaproxy, String defaultProtocol,
							String zapProxyDefaultHost,int zapProxyDefaultPort,
							String zapProxyDefaultApiKey,int zapProxyDefaultTimeoutInSec,
							String zapDefaultDirectory,	boolean useWebProxy,
							String webProxyHost,int webProxyPort,
							String webProxyUser,String webProxyPassword,
							boolean startZAPFirst,int zapDefaultSSHPort,
							String zapDefaultSSHUser,String zapDefaultSSHPassword,
							int zapProxyDefaultTimeoutSSHInSec,	boolean stopZAPAtEnd,
							String authorizedURLs) {
		
		
		super();
		this.zaproxy = zaproxy;
		
		this.zapProxyDefaultTimeoutSSHInSec = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultTimeoutSSHInSec();
		this.zapProxyDefaultTimeoutInSec = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultTimeoutInSec();
		this.defaultProtocol=ZAProxyBuilder.DESCRIPTOR.getDefaultProtocol();
		this.zapProxyDefaultHost = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultHost();
		this.zapProxyDefaultPort = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultPort();
		this.zapProxyDefaultApiKey = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultApiKey();

		this.zapDefaultSSHPort = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPort();
		this.zapDefaultSSHUser = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHUser();
		this.zapDefaultSSHPassword = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPassword();

		this.useWebProxy = ZAProxyBuilder.DESCRIPTOR.isUseWebProxy();
		this.stopZAPAtEnd = ZAProxyBuilder.DESCRIPTOR.isStopZAPAtEnd();
		this.startZAPFirst=ZAProxyBuilder.DESCRIPTOR.isStartZAPFirst();

		this.webProxyHost = ZAProxyBuilder.DESCRIPTOR.getWebProxyHost();
		this.webProxyPort = ZAProxyBuilder.DESCRIPTOR.getWebProxyPort();
		this.webProxyUser = ZAProxyBuilder.DESCRIPTOR.getWebProxyUser();
		this.webProxyPassword = ZAProxyBuilder.DESCRIPTOR.getWebProxyPassword();
		
	
		
		this.zapDefaultDirectory=ZAProxyBuilder.DESCRIPTOR.getZapDefaultDirectory();
 
		
		this.authorizedURLs=ZAProxyBuilder.DESCRIPTOR.getAuthorizedURLs();

	}

	// /*
	// * Getters allows to access member via UI (config.jelly)
	// */
	//
	// public int getTimeoutInSec() {
	// return timeoutInSec;
	// }
	//
	// /**
	// * @return the timeoutSSHInSec
	// */
	// public int getTimeoutSSHInSec() {
	// return timeoutSSHInSec;
	// }
	//
	// /**
	// * @return the useWebProxy
	// */
	// public boolean isUseWebProxy() {
	// return useWebProxy;
	// }
	//
	// /**
	// * @return the startZAP
	// */
	// public boolean isStartZAPFirst() {
	// return startZAPFirst;
	// }
	//
	// /**
	// * @return the stopZAPAtEnd
	// */
	// public boolean isStopZAPAtEnd() {
	// return stopZAPAtEnd;
	// }
	/**
	 * @return the authorizedURLs
	 */
	public String getAuthorizedURLs() {
		return authorizedURLs;
	}
	public ZAProxy getZaproxy() {
		return zaproxy;
	}

	// public String getZapProxyHost() {
	// return zapProxyHost;
	// }
	//
	// public int getZapProxyPort() {
	// return zapProxyPort;
	// }
	//
	// public String getZapProxyKey() {
	// return zapProxyKey;
	// }
	//
	// /**
	// * @return the zapSSHPort
	// */
	// public int getZapSSHPort() {
	// return zapSSHPort;
	// }
	//
	// /**
	// * @return the zapSSHUser
	// */
	// public String getZapSSHUser() {
	// return zapSSHUser;
	// }
	//
	// /**
	// * @return the zapSSHPassword
	// */
	// public String getZapSSHPassword() {
	// return zapSSHPassword;
	// }
	//
	// /**
	// * @return the zapProxyDirectory
	// */
	// public String getZapProxyDirectory() {
	// return zapProxyDirectory;
	// }
	//
	// /**
	// * @return the webProxyHost
	// */
	// public String getWebProxyHost() {
	// return webProxyHost;
	// }
	//
	// /**
	// * @return the webProxyPort
	// */
	// public int getWebProxyPort() {
	// return webProxyPort;
	// }
	//
	// /**
	// * @return the webProxyUser
	// */
	// public String getWebProxyUser() {
	// return webProxyUser;
	// }
	//
	// /**
	// * @return the webProxyPassword
	// */
	// public String getWebProxyPassword() {
	// return webProxyPassword;
	// }
	//
	// /**
	// * @return the pROTOCOL
	// */
	// public String getProtocol() {
	// return protocol;
	// }

	/**
	 * @return the listener
	 */
	public BuildListener getListener() {
		return listener;
	}

	/**
	 * @return the defaultProtocol
	 */
	public String getDefaultProtocol() {
		return defaultProtocol;
	}

	/**
	 * @return the zapProxyDefaultTimeoutInSec
	 */
	public int getZapProxyDefaultTimeoutInSec() {
		return zapProxyDefaultTimeoutInSec;
	}

	/**
	 * @return the zapProxyDefaultTimeoutSSHInSec
	 */
	public int getZapProxyDefaultTimeoutSSHInSec() {
		return zapProxyDefaultTimeoutSSHInSec;
	}

	/**
	 * @return the zapProxyDefaultHost
	 */
	public String getZapProxyDefaultHost() {
		return zapProxyDefaultHost;
	}

	/**
	 * @return the zapProxyDefaultPort
	 */
	public int getZapProxyDefaultPort() {
		return zapProxyDefaultPort;
	}

	/**
	 * @return the zapProxyDefaultApiKey
	 */
	public String getZapProxyDefaultApiKey() {
		return zapProxyDefaultApiKey;
	}

	/**
	 * @return the zapDefaultDirectory
	 */
	public String getZapDefaultDirectory() {
		return zapDefaultDirectory;
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
	 * @param useWebProxy the useWebProxy to set
	 */
	public void setUseWebProxy(boolean useWebProxy) {
		this.useWebProxy = useWebProxy;
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

	// /**
	// * @param zapSSHPort
	// * the zapSSHPort to set
	// */
	// public void setZapSSHPort(int zapSSHPort) {
	// this.zapSSHPort = zapSSHPort;
	// }
	//
	// /**
	// * @param zapSSHUser
	// * the zapSSHUser to set
	// */
	// public void setZapSSHUser(String zapSSHUser) {
	// this.zapSSHUser = zapSSHUser;
	// }
	//
	// /**
	// * @param zapSSHPassword
	// * the zapSSHPassword to set
	// */
	// public void setZapSSHPassword(String zapSSHPassword) {
	// this.zapSSHPassword = zapSSHPassword;
	// }

	// Method called before launching the build
	public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {

		// if(startZAPFirst) {
		// listener.getLogger().println("------- START Prebuild -------");
		//
		// try {
		// Launcher launcher = null;
		// Node node = build.getBuiltOn();
		//
		// // Create launcher according to the build's location (Master or
		// Slave) and the build's OS
		//
		// if("".equals(node.getNodeName())) { // Build on master
		// launcher = new LocalLauncher(listener,
		// build.getWorkspace().getChannel());
		// } else { // Build on slave
		// boolean isUnix;
		// if(
		// "Unix".equals(((SlaveComputer)node.toComputer()).getOSDescription())
		// ) {
		// isUnix = true;
		// } else {
		// isUnix = false;
		// }
		// launcher = new RemoteLauncher(listener,
		// build.getWorkspace().getChannel(), isUnix);
		// }
		//
		//
		//
		//
		// zaproxy.startZAP(build, listener, launcher);
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
		// } catch (Exception e) {
		// e.printStackTrace();
		// listener.error(ExceptionUtils.getStackTrace(e));
		// return false;
		// }
		// listener.getLogger().println("------- END Prebuild -------");
		// }
		// return true;

		// if (startZAPFirst) {
		// listener.getLogger().println("------- START Prebuild -------");
		//
		// listener.getLogger().println("Perform ZAProxy");
		// final String linuxCommand = "sh " +this.getZapProxyDirectory() +
		// "zap.sh -daemon";
		// final String WindowsCommand = this.getZapProxyDirectory() + "zap.bat
		// -daemon";
		//
		//
		// /*
		// * ======================================================= | start
		// * ZAP | =======================================================
		// */
		//
		// listener.getLogger().println("Starting ZAP remotely (SSH)");
		// listener.getLogger().println("SSH PORT : " + this.getZapSSHPort());
		// listener.getLogger().println("SSH USER : " + this.getZapSSHUser());
		// listener.getLogger().println("ZAP DIRECTORY : " +
		// this.getZapProxyDirectory());
		// //SSHConnexion.execCommand(getZapProxyHost(), getZapSSHPort(),
		// getZapSSHUser(), getZapSSHPassword(),linuxCommand, getListener());
		//
		//
		//
		// CredentialsSSHSite site = new
		// CredentialsSSHSite(getZapProxyHost(),getZapSSHPort(),
		// getZapSSHUser(),getZapSSHPassword(),"0","0");
		// // Get the build variables and make sure we substitute the current
		// SSH Server host name
		// try {
		// site.setResolvedHostname(build.getEnvironment(listener).expand(site.getHostname()));
		// } catch (IOException | InterruptedException e1) {
		// // TODO Auto-generated catch block
		// e1.printStackTrace();
		// listener.error(ExceptionUtils.getStackTrace(e1));
		// }
		//
		//
		//
		//
		//// Map<String, String> vars = new HashMap<String, String>();
		//// vars.putAll(build.getEnvironment(listener));
		//// vars.putAll(build.getBuildVariables());
		//// String runtime_cmd = VariableReplacerUtil.replace(linuxCommand,
		// vars);
		//// String scrubbed_cmd = VariableReplacerUtil.scrub(runtime_cmd, vars,
		// build.getSensitiveBuildVariables());
		//
		// if (linuxCommand != null && linuxCommand.trim().length() > 0) {
		//// if (execEachLine) {
		//// listener.getLogger().printf("[SSH] commands:%n%s%n", scrubbed_cmd);
		//// }
		//// else {
		//// listener.getLogger().printf("[SSH] script:%n%s%n", scrubbed_cmd);
		//// }
		// listener.getLogger().printf("%n[SSH] executing...%n");
		// try {
		// return site.executeCommand(listener.getLogger(),
		// linuxCommand,false)==0;
		// } catch (InterruptedException e) {
		// // TODO Auto-generated catch block
		// e.printStackTrace();
		// listener.error(ExceptionUtils.getStackTrace(e));
		// }//, execEachLine) == 0;
		// }
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
		//// Thread queryThread = new Thread() {
		//// public void run() {
		// //SSHConnexion.execCommand(getZapProxyHost(), getZapSSHPort(),
		// getZapSSHUser(), getZapSSHPassword(),linuxCommand, getListener());
		// //SSHConnexion.getQueryShell(getZapProxyHost(), getZapSSHPort(),
		// getZapSSHUser(), getZapSSHPassword(),linuxCommand);
		//
		//// }
		//// };
		//// queryThread.start();
		//
		//
		// listener.getLogger().println("------- END Prebuild -------");
		// }
		//
		// else {
		// listener.getLogger().println("Skip starting ZAP remotely");
		// listener.getLogger().println("startZAPFirst : " + startZAPFirst);
		// }
		return true;
	}

	// Methode appelée pendant le build, c'est ici que zap est lancé
	@Override
	public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {
		
		this.zapProxyDefaultTimeoutSSHInSec = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultTimeoutSSHInSec();
		this.zapProxyDefaultTimeoutInSec = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultTimeoutInSec();
		this.defaultProtocol=ZAProxyBuilder.DESCRIPTOR.getDefaultProtocol();
		this.zapProxyDefaultHost = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultHost();
		this.zapProxyDefaultPort = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultPort();
		this.zapProxyDefaultApiKey = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultApiKey();

		this.zapDefaultSSHPort = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPort();
		this.zapDefaultSSHUser = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHUser();
		this.zapDefaultSSHPassword = ZAProxyBuilder.DESCRIPTOR.getZapDefaultSSHPassword();

		this.useWebProxy = ZAProxyBuilder.DESCRIPTOR.isUseWebProxy();
		this.stopZAPAtEnd = ZAProxyBuilder.DESCRIPTOR.isStopZAPAtEnd();
		this.startZAPFirst=ZAProxyBuilder.DESCRIPTOR.isStartZAPFirst();

		this.webProxyHost = ZAProxyBuilder.DESCRIPTOR.getWebProxyHost();
		this.webProxyPort = ZAProxyBuilder.DESCRIPTOR.getWebProxyPort();
		this.webProxyUser = ZAProxyBuilder.DESCRIPTOR.getWebProxyUser();
		this.webProxyPassword = ZAProxyBuilder.DESCRIPTOR.getWebProxyPassword();
		
	
		
		this.zapDefaultDirectory=ZAProxyBuilder.DESCRIPTOR.getZapDefaultDirectory();
 
		
		this.authorizedURLs=ZAProxyBuilder.DESCRIPTOR.getAuthorizedURLs();
		
		
		
		
		

		if (startZAPFirst) {
			listener.getLogger().println("------- START Prebuild -------");

			listener.getLogger().println("Perform ZAProxy");
			// Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh /opt/ZAP_2.4.2/zap.sh
			// -daemon
			final String linuxCommand = "Xvfb :0.0 & \nexport DISPLAY=:0.0\nsh " + zapDefaultDirectory
					+ "zap.sh -daemon -port " + zapProxyDefaultPort;
			final String WindowsCommand = zapDefaultDirectory + "zap.bat -daemon";

			/*
			 * ======================================================= | start
			 * ZAP | =======================================================
			 */

			listener.getLogger().println("Starting ZAP remotely (SSH)");
			listener.getLogger().println("SSH PORT : " + zapDefaultSSHPort);
			listener.getLogger().println("SSH USER : " + zapDefaultSSHUser);
			listener.getLogger().println("SSH PASSWORD : " + zapDefaultSSHPassword);
			listener.getLogger().println("COMMAND : " + linuxCommand);
			listener.getLogger().println("LISTENER : " + listener);
			listener.getLogger().println("ZAP DIRECTORY : " + zapDefaultDirectory);

			// SSHConnexion.execCommand(getZapProxyHost(), getZapSSHPort(),
			// getZapSSHUser(), getZapSSHPassword(),linuxCommand,
			// getListener());

			// Thread queryThread = new Thread() {
			// public void run() {
			SSHConnexion.execCommand(zapProxyDefaultHost, zapDefaultSSHPort, zapDefaultSSHUser, zapDefaultSSHPassword, linuxCommand, listener);

			// SSHConnexion.getQueryShell(getZapProxyHost(), getZapSSHPort(),
			// getZapSSHUser(), getZapSSHPassword(),linuxCommand);

			// }
			// };
			// queryThread.start();

			listener.getLogger().println("------- END Prebuild -------");
		}

		else {
			listener.getLogger().println("Skip starting ZAP remotely");
			listener.getLogger().println("startZAPFirst : " + startZAPFirst);
		}

		/*
		 * ======================================================= | USE WEB
		 * PROXY | =======================================================
		 */
		if (useWebProxy) {
			// Ici on généralise l'utilisation du proxy web à tous les appels
			// passés via la JVM
			CustomZapClientApi.setWebProxyDetails(webProxyHost, webProxyPort, webProxyUser, webProxyPassword);
		} else {
			listener.getLogger().println("Skip using web proxy");
		}

		this.waitForSuccessfulConnectionToZap(defaultProtocol, zapProxyDefaultHost, zapProxyDefaultPort, zapProxyDefaultTimeoutInSec, listener);

		// try {
		// //à voir à quoi il sert cet appel
		// zaproxy.startZAP(build, listener, launcher);
		// } catch (Exception e) {
		// e.printStackTrace();
		// listener.error(ExceptionUtils.getStackTrace(e));
		// return false;
		// }

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

	// /**
	// * Wait for ZAProxy initialization, so it's ready to use at the end of
	// this
	// * method (otherwise, catch exception). This method is launched on the
	// * remote machine (if there is one)
	// *
	// * @param timeout
	// * the time in sec to try to connect at zap proxy.
	// * @param listener
	// * the listener to display log during the job execution in
	// * jenkins
	// * @throws IOException
	// * @see <a href=
	// * "https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960">
	// * https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960
	// * </a>
	// */
	// private static boolean checkConnectionToZap(String PROTOCOL, String
	// zapProxyHost, int zapProxyPort, int timeout)
	// throws IOException {
	//
	// int timeoutInMs = getMilliseconds(timeout);
	// int connectionTimeoutInMs = timeoutInMs;
	// int pollingIntervalInMs = getMilliseconds(1);
	// boolean connectionSuccessful = false;
	// long startTime = System.currentTimeMillis();
	//
	// URL url;
	//
	// // try {
	// url = new URL(PROTOCOL + "://" + zapProxyHost + ":" + zapProxyPort);
	// connectionSuccessful = checkURL(url, connectionTimeoutInMs);
	// return connectionSuccessful;
	//
	// // } catch (SocketTimeoutException ignore) {
	// //
	// // throw new BuildException("Unable to connect to ZAP's proxy after " +
	// // timeout + " seconds.");
	// //
	// // } catch (IOException ignore) {
	// // // and keep trying but wait some time first...
	// // try {
	// // Thread.sleep(pollingIntervalInMs);
	// // } catch (InterruptedException e) {
	// //
	// // throw new BuildException("The task was interrupted while sleeping
	// // between connection polling.", e);
	// // }
	// //
	// // long ellapsedTime = System.currentTimeMillis() - startTime;
	// // if (ellapsedTime >= timeoutInMs) {
	// //
	// // throw new BuildException("Unable to connect to ZAP's proxy after " +
	// // timeout + " seconds.");
	// // }
	// // connectionTimeoutInMs = (int) (timeoutInMs - ellapsedTime);
	// // }
	//
	// }

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

	
	// private static boolean checkURL(URL url, int connectionTimeoutInMs)
	// throws IOException {
	//
	// /******************************************/
	// HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	// conn.setRequestMethod("GET");
	// conn.setConnectTimeout(connectionTimeoutInMs);
	// System.out.println(String.format("Fetching %s ...", url));
	// // listener.getLogger().println(String.format("Fetching %s ...", url));
	// try {
	// int responseCode = conn.getResponseCode();
	// if (responseCode == 200) {
	// System.out.println(String.format("Site is up, content length = %s",
	// conn.getHeaderField("content-length")));
	// // listener.getLogger().println(String.format("Site is up, content
	// // length = %s", conn.getHeaderField("content-length")));
	// return true;
	// } else {
	// System.out.println(String.format("Site is up, but returns non-ok status =
	// %d", responseCode));
	// // listener.getLogger().println(String.format("Site is up, but
	// // returns non-ok status = %d", responseCode));
	// return false;
	// }
	// } catch (java.net.UnknownHostException e) {
	// System.out.println("Site is down");
	// //listener.getLogger().println("Site is down");
	// return false;
	// }
	// }

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
	// This indicates to Jenkins this is an implementation of an extension point.
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
		private int zapProxyDefaultPort;
		/** API Key configured when ZAProxy is used as proxy */
		private String zapProxyDefaultApiKey;
		private int zapProxyDefaultTimeoutInSec;

		/** ZAP default Directory configured when ZAProxy is used as proxy */
		private String zapDefaultDirectory;

		private boolean useWebProxy;
		public String webProxyHost;
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
			zapProxyDefaultPort = formData.getInt("zapProxyDefaultPort");
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

				@QueryParameter("zapProxyDefaultHost") final String zapProxyHost,
				@QueryParameter("zapProxyDefaultPort") final int zapProxyPort,
				@QueryParameter("zapProxyDefaultApiKey") final String zapProxyKey,
				@QueryParameter("zapProxyDefaultTimeoutInSec") final int timeoutInSec

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

				@QueryParameter("zapProxyDefaultHost") final String zapProxyHost,
				@QueryParameter("zapDefaultSSHPort") final int zapSSHPort,
				@QueryParameter("zapDefaultSSHUser") final String zapSSHUser,
				@QueryParameter("zapDefaultSSHPassword") final String zapSSHPassword,
				@QueryParameter("zapProxyDefaultTimeoutSSHInSec") final int timeoutSSHInSec

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
				SSHConnexion.testSSH(zapProxyHost, zapSSHPort, zapSSHUser, zapSSHPassword,
						getMilliseconds(timeoutSSHInSec));
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
