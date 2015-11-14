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

public class SecurityTools {


	
public static boolean isScannable(String targetURL, String patterns){
		
		String[] urls = patterns.split("\n");
		 

		for (int i = 0; i < urls.length; i++) {
			urls[i] = urls[i].trim();
			if (!urls[i].isEmpty()) {
				
				if (targetURL.matches(urls[i] )){
					
					return true ;
				}
				
				
				
			}

		}

	return false;
 
		
		 
		
	}




}
