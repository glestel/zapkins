package fr.novia.zaproxyplugin.utilities;

import java.io.File;
import java.io.IOException;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;



public class Adapter implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -231406734218154467L;

	public static void adaptTemplate(String birtTemplatePath, String zapReportPath) throws IOException{
		 
		//Adapt the path to the zap xml report
		//<property name="FILELIST">C:\Users\GDRB6297\Documents\Livrables\ZAP_DEV\workspace\ZAPClient_JAVA\templates\xmloutputzap.xml</property>
     
		String birtTemplateXml = new String(Files.readAllBytes(Paths.get(birtTemplatePath)));
		String  newbirtTemplateXml= birtTemplateXml.replaceAll("<property name=\"FILELIST\">(.*)</property>", "<property name=\"FILELIST\">"+Matcher.quoteReplacement(zapReportPath)+"</property>");		
		//newbirtTemplateXml=newbirtTemplateXml.replace("encoding=\"UTF-8\"", "encoding=\"ISO-8859-1\"");	
		
		//conversion des caractères français
		 
		Files.write(Paths.get(birtTemplatePath), newbirtTemplateXml.getBytes());
		
		
		
	}

	public static void adaptZAPReport(String zapReportFilePath) throws IOException {
		// TODO Auto-generated method stub
		//change <?xml version="1.0" encoding="UTF-8"?> to <?xml version="1.0" encoding="ISO-8859-1"?>
		
				String utf8Xml = new String(Files.readAllBytes(Paths.get(zapReportFilePath)));
				String  isoXml= utf8Xml.replace("encoding=\"UTF-8\"", "encoding=\"ISO-8859-1\"");		
				//conversion des caractères français
				//byte [] xmlReportBytes = encode(isoXml.getBytes());
				//Files.write(Paths.get(zapReportFilePath), xmlReportBytes);
				Files.write(Paths.get(zapReportFilePath), isoXml.getBytes());
	}
	
private static byte[] encode(byte[] arr){
		
        Charset utf8charset = Charset.forName("UTF-8");
        Charset iso88591charset = Charset.forName("ISO-8859-15");

        ByteBuffer inputBuffer = ByteBuffer.wrap( arr );

        // decode UTF-8
        CharBuffer data = utf8charset.decode(inputBuffer);

        // encode ISO-8559-1
        ByteBuffer outputBuffer = iso88591charset.encode(data);
        byte[] outputData = outputBuffer.array();

        return outputData;
    }

 

}
