package fr.hackthem.zapkins.utilities;

public class SecurityTools {


	
public static boolean isUrlAuditable(String targetURL, String patterns){
		
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
