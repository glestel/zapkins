package  fr.orange.zaproxyplugin.utilities;

import java.io.Serializable;

public class ProxyCredentials  { // implements Serializable {


	
	/**
	 * 
	 */
	//private static final long serialVersionUID = 6416326735795310263L;
	private String proxyHost="";
	private String proxyPort="";
	private String USER;
	private String PASSWORD ;
	private boolean proxyRequiered=false;
	
	public ProxyCredentials(boolean proxyRequiered){
		 this.proxyRequiered=proxyRequiered;
		
	}
	
	public ProxyCredentials(String proxyHost, String proxyPort, String uSER, String pASSWORD) {
		super();
		this.proxyHost = proxyHost;
		this.proxyPort = proxyPort;
		USER = uSER;
		PASSWORD = pASSWORD;
	}



	/**
	 * @return the proxyHost
	 */
	public String getProxyHost() {
		return proxyHost;
	}



	/**
	 * @param proxyHost the proxyHost to set
	 */
	public void setProxyHost(String proxyHost) {
		this.proxyHost = proxyHost;
	}



	/**
	 * @return the proxyPort
	 */
	public String getProxyPort() {
		return proxyPort;
	}



	/**
	 * @param proxyPort the proxyPort to set
	 */
	public void setProxyPort(String  proxyPort) {
		this.proxyPort = proxyPort;
	}



	/**
	 * @return the uSER
	 */
	public String getUSER() {
		return USER;
	}



	/**
	 * @param uSER the uSER to set
	 */
	public void setUSER(String uSER) {
		USER = uSER;
	}



	/**
	 * @return the pASSWORD
	 */
	public String getPASSWORD() {
		return PASSWORD;
	}



	/**
	 * @param pASSWORD the pASSWORD to set
	 */
	public void setPASSWORD(String pASSWORD) {
		PASSWORD = pASSWORD;
	}



	/**
	 * @return the proxyRequiered
	 */
	public boolean isProxyRequiered() {
		return proxyRequiered;
	}



	/**
	 * @param proxyRequiered the proxyRequiered to set
	 */
	public void setProxyRequiered(boolean proxyRequiered) {
		this.proxyRequiered = proxyRequiered;
	}


 
	
	
}
