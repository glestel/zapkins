package fr.orange.zaproxyplugin.utilities;

import java.util.Random;

public class Security {

static final int range = ( 65535 - 49152 );// Private Ports are those from 49152 through 65535	
	
	
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




}
