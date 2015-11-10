package  fr.novia.zaproxyplugin.utilities;

import java.util.Properties;
import java.io.IOException;
import java.io.Serializable;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.File;
import java.io.FileInputStream;

public class PropertyLoader { //implements Serializable {
	

   /**
	 * 
	 */
	//private static final long serialVersionUID = -7550424203698393051L;
/**
    * Charge la liste des propriétés contenu dans le fichier spécifié
    *
    * @param filename le fichier contenant les propriétés
    * @return un objet Properties contenant les propriétés du fichier
    */
  private static Properties load(String filename) {
      
	  Properties properties = new Properties();
      FileInputStream input = null;
      
      
	try {
		File file = new File(filename);
		if(file.createNewFile())
			System.out.println("File : "+filename+" created ");
		
		input = new FileInputStream(filename);
		 properties.load(input);
         return properties;
         
         
         
	} catch (FileNotFoundException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
			      
	    
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
       

              finally{

         try {
			input.close();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

      }
     return null;
   }
   
   
   public static void update(String Key, String Value, String fileName) {
	   FileInputStream in;
	try {
		in = new FileInputStream(fileName);
		Properties props = new Properties();
	       props.load(in);
	       in.close();

	       FileOutputStream out = new FileOutputStream(fileName);
	       props.setProperty(Key, Value);
	       props.store(out, null);
	       out.close();
	} catch (FileNotFoundException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	} catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
       
   }
  public static String getValueFromKey(String Key,String defaultValue, String fileName) {
	  
	  Properties prop = load(fileName);
	  return prop.getProperty(Key, defaultValue);
	  
	  
  }
   public static void main(String[] args){
      try{
//         // chargement des propriétés
//         Properties prop = PropertyLoader.load();
//
//         // Affichage des propriétés
//        
//         // Si la propriété n'existe pas, retourne la valeur par défaut "vide"
    	  
    	  
    	  String fileName=new File(".").getAbsolutePath()+"/proxy.properties";
         System.out.println(PropertyLoader.getValueFromKey("USER","Vide",fileName));
         
         update("USER","test2014",fileName);
         
         

         // Affichage des propriétés
        
         // Si la propriété n'existe pas, retourne la valeur par défaut "vide"
         System.out.println(PropertyLoader.getValueFromKey("USER","Vide",fileName));
         
      }
      catch(Exception e){
         e.printStackTrace();
      }
   }
}