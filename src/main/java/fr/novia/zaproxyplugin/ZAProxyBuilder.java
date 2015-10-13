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
import hudson.model.BuildListener;
import hudson.model.Descriptor;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject; 
import hudson.remoting.VirtualChannel; 
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import jenkins.model.Jenkins;
import net.sf.json.JSONObject; 
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.tools.ant.BuildException;
import org.jenkinsci.remoting.RoleChecker;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.StaplerRequest;

import fr.novia.zaproxyplugin.utilities.SSHConnexion;

import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
 

/**
 * /!\ 
 * Au jour du 27/03/2015
 * La version 2.3.1 de ZAPROXY ne contient pas le plugin "pscanrules-release-10.zap" qui sert Ã  
 * remonter les alertes lors d'un scan passif (spider). Il faut donc ajouter ce plugin manuellement ou 
 * tÃ©lÃ©charger la prochaine version de ZAPROXY (2.4) via Custom Tools Plugin (et non la 2.3.1) 
 * /!\
 * 
 * The main class of the plugin. This class adds a build step in a Jenkins job that allows you
 * to launch the ZAProxy security tool and get alerts reports from it.
 * 
 * @author ludovic.roucoux
 *
 */
public class ZAProxyBuilder extends Builder {
	
	private final int timeoutInSec=15;	
	private static final int MILLISECONDS_IN_SECOND = 1000;
	private static final String PROTOCOL = "http";
	
	
	private BuildListener listener;
	
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
	
	
	
	/************ SSH ****************/
	
	
	/** SSH PORT  configured when ZAProxy is used as proxy */
	private int zapSSHPort;
	

	/** SSH USER configured when ZAProxy is used as proxy */
	private String  zapSSHUser;
	
	
	/** SSH PASSWORD configured when ZAProxy is used as proxy */
	private String  zapSSHPassword;
	
	
	
	/** proxyWeb host */
	private final String webProxyHost;
	/** proxyWeb port*/
	private final int webProxyPort;
	/** proxyWeb username*/
	private final String webProxyUser;
	/** proxyWeb password */
	private final String webProxyPassword;
	
	/** use or not a proxyWeb  */
	private final boolean useWebProxy;
	
	/** start ZAP remotely  */
	private final boolean startZAPFirst;
 
	
	
	
	// Fields in fr/novia/zaproxyplugin/ZAProxyBuilder/config.jelly must match the parameter names in the "DataBoundConstructor"
	@DataBoundConstructor 
	public ZAProxyBuilder(ZAProxy zaproxy, String zapProxyHost, int zapProxyPort, int zapSSHPort, String zapSSHUser, String zapSSHPassword,  boolean startZAPFirst, boolean useWebProxy, String zapProxyDirectory,  String zapProxyKey,
			String webProxyHost, int webProxyPort, String webProxyUser, String webProxyPassword) {
		super();
		this.zaproxy = zaproxy;
		this.zapProxyHost = zapProxyHost;
		this.zapProxyPort = zapProxyPort;
		this.zapProxyKey = zapProxyKey;	
		this.zapProxyDirectory=zapProxyDirectory;
		
		this.zaproxy.setZapProxyHost(zapProxyHost);
		this.zaproxy.setZapProxyPort(zapProxyPort);
		this.zaproxy.setZapProxyApiKey(zapProxyKey);
		this.zaproxy.setZapProxyDirectory(zapProxyDirectory);
		
		this.useWebProxy=useWebProxy;
		this.webProxyHost = webProxyHost;
		this.webProxyPort = webProxyPort;
		this.webProxyUser = webProxyUser;
		this.webProxyPassword = webProxyPassword;
		
		this.zaproxy.setUseWebProxy(useWebProxy);
		this.zaproxy.setWebProxyHost(webProxyHost);
		this.zaproxy.setWebProxyPort(webProxyPort);
		this.zaproxy.setWebProxyUser(webProxyUser);
		this.zaproxy.setWebProxyPassword(webProxyPassword);
		
		this.startZAPFirst=startZAPFirst;
		 
		this.zapSSHPort=zapSSHPort;
		this.zapSSHUser=zapSSHUser;
		this.zapSSHPassword=zapSSHPassword;
				
		this.zaproxy.setZapSSHPort(zapSSHPort);
		this.zaproxy.setZapSSHUser(zapSSHUser);
		this.zaproxy.setZapSSHPassword(zapSSHPassword);
		 
		
		
		
		
	}

	/*
	 * Getters allows to access member via UI (config.jelly)
	 */
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
	
	// Overridden for better type safety.
	// If your plugin doesn't really define any property on Descriptor,
	// you don't have to do this.
	@Override
	public ZAProxyBuilderDescriptorImpl getDescriptor() {
		return (ZAProxyBuilderDescriptorImpl)super.getDescriptor();
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
	 * @return the listener
	 */
	public BuildListener getListener() {
		return listener;
	}

	/**
	 * @param listener the listener to set
	 */
	public void setListener(BuildListener listener) {
		this.listener = listener;
	}

	// Method called before launching the build
	public boolean prebuild(AbstractBuild<?, ?> build, BuildListener listener) {	
        this.setListener(listener);
		return true;
	}

	// Methode appelée pendant le build, c'est ici que zap est lancé
	@Override
	public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener) {
		
			
		listener.getLogger().println("Perform ZAProxy");
		final String command=this.getZapProxyDirectory()+"zap.sh";
		/* ======================================================= 
		 * |                 start ZAP                       |
		 * ======================================================= 
		 */
 
		if(startZAPFirst){
			
		    
			listener.getLogger().println("Starting ZAP remotely (SSH)");
			listener.getLogger().println("SSH PORT : "+this.getZapSSHPort());
			listener.getLogger().println("SSH USER : "+this.getZapSSHUser());
			listener.getLogger().println("SSH PASSWORD : "+this.getZapSSHPassword());
			listener.getLogger().println("ZAP DIRECTORY : "+this.getZapProxyDirectory());
			
			
			Thread queryThread = new Thread() {
			public void run() {
								SSHConnexion.execCommand(getZapProxyHost(), getZapSSHPort(), getZapSSHUser(), getZapSSHPassword(), "sh "+command+" -daemon", getListener());
								}};
			queryThread.start();
		}
		else {
			listener.getLogger().println("Skip starting ZAP remotely");
			listener.getLogger().println("startZAPFirst : "+startZAPFirst);
		}
		
		/* ======================================================= 
		 * |                 USE WEB PROXY                       |
		 * ======================================================= 
		 */
		if(useWebProxy){
			    
			CustomZapClientApi.setWebProxyDetails(webProxyHost, webProxyPort, webProxyUser, webProxyPassword);
		}
		else {
			listener.getLogger().println("Skip using web proxy");
		}
		
		
		this.waitForSuccessfulConnectionToZap(zapProxyHost, zapProxyPort, timeoutInSec, listener);
		
		try {
				zaproxy.startZAP(build, listener, launcher);
			} catch (Exception e) {
				e.printStackTrace();
				listener.error(ExceptionUtils.getStackTrace(e));
				return false;
			}
		 
		
		
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
	 * Wait for ZAProxy initialization, so it's ready to use at the end of this method
	 * (otherwise, catch exception). This method is launched on the remote machine (if there is one)
	 *   
	 * @param timeout the time in sec to try to connect at zap proxy. 
	 * @param listener the listener to display log during the job execution in jenkins
	 * @see <a href="https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960">
	 * 		https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960</a>
	 */
	private void waitForSuccessfulConnectionToZap(String zapProxyHost, int zapProxyPort , int timeout, BuildListener listener) {	
			
		int timeoutInMs = getMilliseconds(timeout);
		int connectionTimeoutInMs = timeoutInMs;
		int pollingIntervalInMs = getMilliseconds(1);
		boolean connectionSuccessful = false;
		long startTime = System.currentTimeMillis();
	 
		URL url;

		do {
			try {
				url = new URL(PROTOCOL+"://"+zapProxyHost+":"+zapProxyPort);
				connectionSuccessful=checkURL(url, connectionTimeoutInMs, listener);
				

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
	
	/**
	 * Converts seconds in milliseconds.
	 * @param seconds the time in second to convert
	 * @return the time in milliseconds
	 */
	private static int getMilliseconds(int seconds) {
		return seconds * MILLISECONDS_IN_SECOND;
	}

	private boolean  checkURL(URL url, int connectionTimeoutInMs, BuildListener listener ) throws IOException {
		

		
		/******************************************/
	    HttpURLConnection conn = (HttpURLConnection) url.openConnection();
	    conn.setRequestMethod("GET");
	    conn.setConnectTimeout(connectionTimeoutInMs);
	    System.out.println(String.format("Fetching %s ...", url));
	    listener.getLogger().println(String.format("Fetching %s ...", url));
	    try {
	        int responseCode = conn.getResponseCode();
	        if (responseCode == 200) {
	            System.out.println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
	            listener.getLogger().println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
	            return true;
	        } else {
	            System.out.println(String.format("Site is up, but returns non-ok status = %d", responseCode));
	            listener.getLogger().println(String.format("Site is up, but returns non-ok status = %d", responseCode));
	            return false;
	        }
	    } catch (java.net.UnknownHostException e) {
	        System.out.println("Site is down");
	        listener.getLogger().println("Site is down");
	        return false; 
	    }
	}

	/**
	 * Descriptor for {@link ZAProxyBuilder}. Used as a singleton.
	 * The class is marked as public so that it can be accessed from views.
	 *
	 * <p>
	 * See <tt>src/main/resources/fr/novia/zaproxyplugin/ZAProxyBuilder/*.jelly</tt>
	 * for the actual HTML fragment for the configuration screen.
	 */
	@Extension // This indicates to Jenkins this is an implementation of an extension point.
	public static final class ZAProxyBuilderDescriptorImpl extends BuildStepDescriptor<Builder> {
		/**
		 * To persist global configuration information,
		 * simply store it in a field and call save().
		 *
		 * <p>
		 * If you don't want fields to be persisted, use <tt>transient</tt>.
		 */
		private String zapProxyDefaultHost;
		private int zapProxyDefaultPort;
		/** API Key configured when ZAProxy is used as proxy */
		private  String zapProxyDefaultApiKey;
		
		/** ZAP default Directory configured when ZAProxy is used as proxy */
		private  String zapDefaultDirectory ;
		
		/** ZAP default SSH port configured when ZAProxy is used as proxy */
		private  int  zapDefaultSSHPort ;
		
		/** ZAP default SSH port configured when ZAProxy is used as proxy */
		private  String  zapDefaultSSHUser ;
		
		/** ZAP default SSH port configured when ZAProxy is used as proxy */
		private  String  zapDefaultSSHPassword ;
		
		
 		/**
		 * In order to load the persisted global configuration, you have to
		 * call load() in the constructor.
		 */
		public ZAProxyBuilderDescriptorImpl() {
			load();
		}
		
		@Override
		public boolean isApplicable(Class<? extends AbstractProject> aClass) {
			// Indicates that this builder can be used with all kinds of project types
			return true;
		}

		/**
		 * This human readable name is used in the configuration screen.
		 */
		@Override
		public String getDisplayName() {
			return "Lancer ZAProxy";
		}

		@Override
		public boolean configure(StaplerRequest req, JSONObject formData) throws FormException {
			// To persist global configuration information,
			// set that to properties and call save().
			zapProxyDefaultHost = formData.getString("zapProxyDefaultHost");
			zapProxyDefaultPort = formData.getInt("zapProxyDefaultPort");
			zapProxyDefaultApiKey=formData.getString("zapProxyDefaultApiKey");
			zapDefaultDirectory=formData.getString("zapDefaultDirectory");
			
			
			zapDefaultSSHPort=formData.getInt("zapDefaultSSHPort");			
			zapDefaultSSHUser=formData.getString("zapDefaultSSHUser");			
			zapDefaultSSHPassword=formData.getString("zapDefaultSSHPassword");
			
			
			// ^Can also use req.bindJSON(this, formData);
			//  (easier when there are many fields; need set* methods for this, like setUseFrench)
			save();
			return super.configure(req,formData);
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

	}
	
	/**
	 * Used to execute ZAP remotely.
	 * 
	 * @author ludovic.roucoux
	 *
	 */
	private static class ZAProxyCallable implements FileCallable<Boolean> {

		private static final long serialVersionUID = -313398999885177679L;
		
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
