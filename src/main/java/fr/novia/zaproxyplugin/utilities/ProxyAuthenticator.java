package fr.novia.zaproxyplugin.utilities;

import java.io.Serializable;
import java.net.Authenticator;
import java.net.PasswordAuthentication;

public class ProxyAuthenticator extends Authenticator implements Serializable {


	    /**
	 * 
	 */
	private static final long serialVersionUID = -1673622686122595507L;
		private String user, password;

	    public ProxyAuthenticator(String user, String password) {
	        this.user = user;
	        this.password = password;
	    }

	    protected PasswordAuthentication getPasswordAuthentication() {
	        return new PasswordAuthentication(user, password.toCharArray());
	    }
	}	
	

