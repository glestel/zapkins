package fr.orange.zaproxyplugin.utilities;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.ProtocolException;
import java.net.Proxy;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.Random;

import org.apache.tools.ant.BuildException;

import hudson.model.BuildListener;

public class HttpUtilities {
	
	
	
	static final int range = ( 65535 - 49152 );// Private Ports are those from 49152 through 65535	
	private static final int MILLISECONDS_IN_SECOND = 1000;		
	
	

public static synchronized Integer getPortNumber()
{
    Random candidateInt = new Random();//
    int cadidatePort = (candidateInt.nextInt(49152) + range);
    if((cadidatePort < 49152) || (cadidatePort > 65535))
    {
        do
        {
            cadidatePort = (candidateInt.nextInt(49152) + range);
        }
        while((cadidatePort < 49152) || (cadidatePort > 65535));
        return new Integer(cadidatePort);
    }
    else
    {
        return new Integer(cadidatePort);
    }

}

///**
// * Wait for ZAProxy initialization, so it's ready to use at the end of this
// * method (otherwise, catch exception). This method is launched on the
// * remote machine (if there is one)
// * 
// * @param timeout
// *            the time in sec to try to connect at zap proxy.
// * @param listener
// *            the listener to display log during the job execution in
// *            jenkins
// * @see <a href=
// *      "https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960">
// *      https://groups.google.com/forum/#!topic/zaproxy-develop/gZxYp8Og960
// *      </a>
// */
//private void waitForSuccessfulConnectionToZap(String protocol, String zapProxyHost, int zapProxyPort, int timeout,
//		BuildListener listener) {
//
//	int timeoutInMs = getMilliseconds(timeout);
//	int connectionTimeoutInMs = timeoutInMs;
//	int pollingIntervalInMs = getMilliseconds(1);
//	boolean connectionSuccessful = false;
//	long startTime = System.currentTimeMillis();
//
//	URL url;
//
//	do {
//		try {
//			listener.getLogger().println(protocol + "://" + zapProxyHost + ":" + zapProxyPort);
//			url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);
//
//			connectionSuccessful = checkURL(url, connectionTimeoutInMs, listener);
//
//		} catch (SocketTimeoutException ignore) {
//
//			throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
//
//		} catch (IOException ignore) {
//			// and keep trying but wait some time first...
//			try {
//				Thread.sleep(pollingIntervalInMs);
//			} catch (InterruptedException e) {
//
//				throw new BuildException("The task was interrupted while sleeping between connection polling.", e);
//			}
//
//			long ellapsedTime = System.currentTimeMillis() - startTime;
//			if (ellapsedTime >= timeoutInMs) {
//
//				throw new BuildException("Unable to connect to ZAP's proxy after " + timeout + " seconds.");
//			}
//			connectionTimeoutInMs = (int) (timeoutInMs - ellapsedTime);
//		}
//	} while (!connectionSuccessful);
//}

 

/**
 * Converts seconds in milliseconds.
 * 
 * @param seconds
 *            the time in second to convert
 * @return the time in milliseconds
 */
public static int getMilliseconds(int seconds) {
	return seconds * MILLISECONDS_IN_SECOND;
}

public static boolean  portIsToken(Proxy proxy,String protocol, String zapProxyHost, int zapProxyPort, int timeout,  BuildListener listener)   {
	

	try {
		
		listener.getLogger().println(protocol + "://" + zapProxyHost + ":" + zapProxyPort);
		URL url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);
	    int connectionTimeoutInMs=getMilliseconds(timeout);
		/******************************************/
	    HttpURLConnection conn;
	    if(proxy != null){
	    	conn = (HttpURLConnection) url.openConnection(proxy);
	    }
	    else
	    {
	    	conn = (HttpURLConnection) url.openConnection();
	    }	
		
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
	
		
		
		
		
		
	} catch (ProtocolException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	return false;
	

}

public static boolean  portIsToken(Proxy proxy,String protocol, String zapProxyHost, int zapProxyPort, int timeout )   {
	

	try {
		
	 
		URL url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);
	    int connectionTimeoutInMs=getMilliseconds(timeout);
		/******************************************/
	    HttpURLConnection conn;
	    if(proxy != null){
	    	conn = (HttpURLConnection) url.openConnection(proxy);
	    }
	    else
	    {
	    	conn = (HttpURLConnection) url.openConnection();
	    }	
		
		conn.setRequestMethod("GET");
		
		conn.setConnectTimeout(connectionTimeoutInMs);
		System.out.println(String.format("Fetching %s ...", url));
	 
		// try {
		int responseCode = conn.getResponseCode();
		if (responseCode == 200) {
			System.out.println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
		 
			return true;
		} else {
			System.out.println(String.format("Site is up, but returns non-ok status = %d", responseCode));
		 
			return false;
		}
	
		
		
		
		
		
	} catch (ProtocolException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		//e.printStackTrace();
		return false;
	}
	
	return false;
	

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
public static  void waitForSuccessfulConnectionToZap(Proxy proxy,String protocol, String zapProxyHost, int zapProxyPort, int timeout) {

	int timeoutInMs = getMilliseconds(timeout);
	int connectionTimeoutInMs = timeoutInMs;
	int pollingIntervalInMs = getMilliseconds(1);
	boolean connectionSuccessful = false;
	long startTime = System.currentTimeMillis();

	URL url;

	do {
		try {
			 
			url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);

			connectionSuccessful = checkURL(proxy,url, connectionTimeoutInMs );

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

public static  void waitForSuccessfulConnectionToZap(Proxy proxy,String protocol, String zapProxyHost, int zapProxyPort, int timeout, BuildListener listener) {

	int timeoutInMs = getMilliseconds(timeout);
	int connectionTimeoutInMs = timeoutInMs;
	int pollingIntervalInMs = getMilliseconds(1);
	boolean connectionSuccessful = false;
	long startTime = System.currentTimeMillis();

	URL url;

	do {
		try {
			 
			url = new URL(protocol + "://" + zapProxyHost + ":" + zapProxyPort);

			connectionSuccessful = checkURL(proxy,url, connectionTimeoutInMs,listener );

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

 

private static boolean checkURL(Proxy proxy,URL url, int connectionTimeoutInMs ) throws IOException {

	/******************************************/
	HttpURLConnection conn;
	if(proxy != null){
	conn = (HttpURLConnection) url.openConnection(proxy);
	}
	else {
		
	conn = (HttpURLConnection) url.openConnection();	
	}
	conn.setRequestMethod("GET");
	conn.setConnectTimeout(connectionTimeoutInMs);
	System.out.println(String.format("Fetching %s ...", url));
	 
	// try {
	int responseCode = conn.getResponseCode();
	if (responseCode == 200) {
		System.out.println(String.format("Site is up, content length = %s", conn.getHeaderField("content-length")));
		 
		return true;
	} else {
		System.out.println(String.format("Site is up, but returns non-ok status = %d", responseCode));
		 
		return false;
	}
}
	
 	
private static boolean checkURL(Proxy proxy,URL url, int connectionTimeoutInMs, BuildListener listener  ) throws IOException {

	/******************************************/
	HttpURLConnection conn;
	if(proxy != null){
	conn = (HttpURLConnection) url.openConnection(proxy);
	}
	else {
		
	conn = (HttpURLConnection) url.openConnection();	
	}
	conn.setRequestMethod("GET");
	conn.setConnectTimeout(connectionTimeoutInMs);
	System.out.println(String.format("Fetching %s ...", url));
	listener.getLogger().println(String.format("Fetching %s ...", url));
	 
	// try {
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
}
		
	
	
	
	
	

}
