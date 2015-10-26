package fr.novia.zaproxyplugin.utilities;


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.MalformedURLException;
import java.net.Proxy;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;
import org.zaproxy.clientapi.core.ApiResponse;
import org.zaproxy.clientapi.core.ApiResponseElement;
import org.zaproxy.clientapi.core.ApiResponseList;
import org.zaproxy.clientapi.core.ClientApiException;

import fr.novia.zaproxyplugin.CustomZapClientApi;

public class TestProxy {

	/**
	 * @param args
	 * @throws IOException 
	 */
	public static void main(String[] args) throws IOException {
		// TODO Auto-generated method stub
		
		Authenticator.setDefault(new ProxyAuthenticator("aazougarh", "Karkachan@2014"));  
		Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("10.234.168.99", 8080));
		
		try {
			///pscan/action/enableAllScanners/?zapapiformat=JSON&apikey=wbxvnvxcw%2Cwc
			Map<String, String> map = null;
			map = new HashMap<String, String>();
			String apikey="p5vocslricjcadf8333rnkv0e6";
			if (apikey != null) {
				map.put("apikey", apikey);
			}
			//http://10.107.2.102:8080/XML/core/view/version/?zapapiformat=XML
			ApiResponseElement configParamsList = (ApiResponseElement) CustomZapClientApi.sendRequest("http","10.107.2.102",8080,"xml","core","view","version",map,proxy,15);
			
			System.out.println(configParamsList.getName());
			System.out.println(configParamsList.getValue());
		} catch (ParserConfigurationException | SAXException | ClientApiException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	 	
//		
//		String line="";
//		URL url = null;
//		try {
//			url = new URL("https://mail.google.com");
//		} catch (MalformedURLException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		 HttpURLConnection uc = (HttpURLConnection)url.openConnection(proxy);
//		 
//		 uc.connect();
//         StringBuffer page=new StringBuffer();
// 		 StringBuffer tmp = new StringBuffer();
// 		 BufferedReader in = new BufferedReader(new InputStreamReader(uc.getInputStream()));
// 		while ((line = in.readLine()) != null){
// 		       page.append(line + "\n");
// 		      System.out.println(page.toString());
// 		    
// 		}
// 		System.out.println("page.toString()");

	}

}