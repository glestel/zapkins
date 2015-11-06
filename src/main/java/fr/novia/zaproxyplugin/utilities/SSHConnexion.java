package fr.novia.zaproxyplugin.utilities;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.util.Properties;

import org.apache.commons.lang.exception.ExceptionUtils;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import hudson.model.BuildListener;

public class SSHConnexion { //implements Serializable {
	
	
	/**
	 * 
	 */
//	private static final long serialVersionUID = -1718331299868798947L;

	public SSHConnexion(){
		
	}
	
	
public static boolean startZAPDaemon(String HOST, int PORT, String USER, String PASSWORD , String ZAPPATH, BuildListener listener){
    	
    	JSch jsch = new JSch();
		try {

			Session session = jsch.getSession(USER, HOST, PORT);
			session.setPassword(PASSWORD);
			session.setConfig("StrictHostKeyChecking", "no");
//			 Enable agent-forwarding.
//			    ((ChannelShell)channel).setAgentForwarding(true);
			
			
			session.connect(30000); // making a connection with timeout.

			
			Channel channel = session.openChannel("exec");
			((ChannelExec)channel).setXForwarding(true);
			 
			 
			channel.setInputStream(null);
			((ChannelExec) channel).setErrStream(System.err);			
			InputStream in = channel.getInputStream();			 
			 

			 
			 
			String command = "sh " + ZAPPATH + " -daemon";
			((ChannelExec) channel).setCommand(command);

			
			

			channel.connect();
			
			

			byte[] tmp = new byte[1024];
			
			while (true) {
				
				   /************************************/
				
					while (in.available() > 0) 
					{
						int i = in.read(tmp, 0, 1024);
						if (i < 0)
							break;
						System.out.print(new String(tmp, 0, i));
						//listener.getLogger().println(new String(tmp, 0, i));
						 
					}
					
					/************************************/
					
					if (channel.isClosed()) {
						if (in.available() > 0)
							continue;
						System.out.println("exit-status: " + channel.getExitStatus());
						System.out.println("Chanel closed");
						listener.getLogger().println("exit-status: " + channel.getExitStatus());
						listener.getLogger().println("Chanel closed");
						break;
					}
					
					/************************************/
					try {
						Thread.sleep(1000);
					} catch (Exception ee) {
					}
			}
			
			System.out.println("exit-status: " + channel.getExitStatus());
			listener.getLogger().println("exit-status: " + channel.getExitStatus());
			channel.disconnect();
			session.disconnect();
			return true ;

		} catch (JSchException e) {
			 
			e.printStackTrace();}
//		 catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		
catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
    	
    	
    	
		return false;
    	
    	
    	
    }

public static boolean execCommand(String HOST, int PORT, String USER, String PASSWORD , String command,BuildListener listener){
	
	JSch jsch = new JSch();
	try {
		//session
		Session session = jsch.getSession(USER, HOST, PORT);
		session.setPassword(PASSWORD);
		session.setConfig("StrictHostKeyChecking", "no");
		session.connect(2000); // making a connection with timeout.		
		
		//channel
		Channel channel = session.openChannel("exec");
		channel.setInputStream(null);
		
		//channel exec 
		ChannelExec channelExec = (ChannelExec) channel ; 
		channelExec.setCommand(command);
		channelExec.setErrStream(System.err);
		
		
		InputStream in = channel.getInputStream();
		channel.connect();

		
		byte[] tmp = new byte[1024];
		 
		
//		while (true) {
//			while (in.available() > 0) {
//				int i = in.read(tmp, 0, 1024);
//				if (i < 0)
//					break;
//				System.out.print(new String(tmp, 0, i));
//				listener.getLogger().println(new String(tmp, 0, i));
//				
//				System.out.println("exit-status: " + channel.getExitStatus());
//				listener.getLogger().println("exit-status: " + channel.getExitStatus());
//			}
//			if (channel.isClosed()) {
//				if (in.available() > 0)
//					continue;
//				System.out.println("exit-status (channel is closed): " + channel.getExitStatus());
//				listener.getLogger().println("exit-status (channel is closed): " + channel.getExitStatus());
//				break;
//			}
			try {
				Thread.sleep(5000);// 1 seconde
			} catch (Exception ee) {
				listener.error(ExceptionUtils.getStackTrace(ee));
				ee.printStackTrace();
			}
//		}
		
		System.out.println("exit-status (FIN): " + channel.getExitStatus());
		listener.getLogger().println("exit-status (FIN): " + channel.getExitStatus());
		
		channel.disconnect();
		session.disconnect();

	} catch (JSchException e) {
		// TODO Auto-generated catch block
		listener.error(ExceptionUtils.getStackTrace(e));
		e.printStackTrace();}
//	 catch (IOException e) {
//		// TODO Auto-generated catch block
//		e.printStackTrace();
//	}
//	
catch (IOException e) {
		// TODO Auto-generated catch block
	listener.error(ExceptionUtils.getStackTrace(e));
		e.printStackTrace();
	}
	
	
	
	
	
	return false;
	
	
	
}
public static boolean execCommand2(String HOST, int PORT, String USER, String PASSWORD , String command,BuildListener listener){
	
	JSch jsch = new JSch();
	try {

		Session session = jsch.getSession(USER, HOST, PORT);
		session.setPassword(PASSWORD);
	    Properties config = new Properties();
	    config.put("StrictHostKeyChecking", "no");
		session.setConfig(config);
		session.connect(); // making a connection with timeout.

		
		Channel channel = session.openChannel("exec");
		ChannelExec ce = (ChannelExec) channel;
		// Enable agent-forwarding.
	   // ((ChannelShell)channel).setAgentForwarding(true);
		ce.setCommand(command);		
		ce.setErrStream(System.err);
		ce.connect();
		
		
		BufferedReader reader = new BufferedReader(new InputStreamReader(ce.getInputStream()));
	    String line;
	    while ((line = reader.readLine()) != null) {
	      System.out.println(line);
	    }

	    ce.disconnect();
	    session.disconnect();
  

	} catch (JSchException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();}
//	 catch (IOException e) {
//		// TODO Auto-generated catch block
//		e.printStackTrace();
//	}
//	
catch (IOException e) {
		// TODO Auto-generated catch block
		e.printStackTrace();
	}
	
	
	
	
	
	return false;
	
	
	
}

public static String getQueryShell(String HOST, int PORT, String USER, String PASSWORD, String p_sCommand)
{
    StringBuilder sbResponse = null;

    try
    {
        JSch jsch=new JSch();  

//        String host = URL;
//        String user=host.substring(0, host.indexOf('@'));
//        host = host.substring(host.indexOf('@')+1);
//        String password = PASSWORD;

        Session session=jsch.getSession(USER,HOST,PORT);
        java.util.Properties config = new java.util.Properties();
        config.put("StrictHostKeyChecking","no");
        session.setConfig(config);
        // username and password will be given via UserInfo interface.
        session.setPassword(PASSWORD);
        session.connect();

        Channel channel=session.openChannel("exec");
        ((ChannelExec)channel).setCommand(p_sCommand);

        channel.setInputStream(null);

        ((ChannelExec)channel).setErrStream(System.err);

        InputStream in=channel.getInputStream();

        channel.connect();

        byte[] tmp=new byte[1024];

        sbResponse = new StringBuilder();

        while(true)
        {
            while(in.available()>0)
            {
                int i=in.read(tmp, 0, 1024);

                if(i<0)break;

                sbResponse.append(new String(tmp, 0, i));
            }
            if(channel.isClosed())
            {
                //System.out.println("exit-status: " + channel.getExitStatus());
                break;
            }

            try
            {
                Thread.sleep(1000);
            }
            catch(Exception ee)
            {

            }
        }
        channel.disconnect();
        session.disconnect();
    }
    catch(Exception e)
    {
        System.out.println(e);
    }

    return sbResponse.toString();
}
//private void sendCommand(Channel channel, String command) {
//    try {
//        //
//        this.channelExec = (ChannelExec) channel;
//        this.channelExec.setCommand(command);
//        //channel.setInputStream(null);
//        channel.setOutputStream(System.out);
//        this.is = channel.getInputStream();
//        channel.connect();
//        byte[] buffer = new byte[1024];
//        while (channel.getExitStatus() == -1) {
//            while (is.available() > 0) {
//                int i = is.read(buffer, 0, 1024);
//               // System.out.println("i= " + i);
//                if (i < 0) {
//                   // System.out.println("breaking");
//                    break;
//                }
//                String string = new String(buffer, 0, i);                    
//                output = output.concat(string);
//                //System.out.println("String= " + string);
//
//            }
//
//            if (channel.isClosed()) {
//                //System.out.println("exit-status: " + channel.getExitStatus());
//                break;
//            }
//
//        }
//        is.close();            
//        channel.disconnect();
//        this.session.disconnect();
//        System.out.println("Done");
//
//    } catch (IOException ex) {
//        System.out.println("ERROR: " + ex);
//        Logger.getLogger(SSH.class.getName()).log(Level.SEVERE, null, ex);
//    } catch (JSchException ex) {
//        System.out.println("ERROR: " + ex);
//        Logger.getLogger(SSH.class.getName()).log(Level.SEVERE, null, ex);
//    }
//
//}

public static void  testSSH(String HOST, int PORT, String USER, String PASSWORD, int timeoutInMilliSec  ) throws JSchException, IOException{
	
	JSch jsch = new JSch();
 

		Session session = jsch.getSession(USER, HOST, PORT);
		session.setPassword(PASSWORD);
		session.setConfig("StrictHostKeyChecking", "no");
		session.connect(timeoutInMilliSec); // making a connection with timeout.

		
		Channel channel = session.openChannel("shell");
		// Enable agent-forwarding.
	   // ((ChannelShell)channel).setAgentForwarding(true);
		//((ChannelExec) channel).setCommand(command);
//
//		channel.setInputStream(null);
//		((ChannelExec) channel).setErrStream(System.err);
//		
//		
//		
//		InputStream in = channel.getInputStream();

		channel.connect();
//
//		byte[] tmp = new byte[1024];
//		
//		while (true) {
//			while (in.available() > 0) {
//				int i = in.read(tmp, 0, 1024);
//				if (i < 0)
//					break;
//				System.out.print(new String(tmp, 0, i));
//				//listener.getLogger().println(new String(tmp, 0, i));
//				System.out.println("exit-status: " + channel.getExitStatus());
//				//listener.getLogger().println("exit-status: " + channel.getExitStatus());
//			}
//			if (channel.isClosed()) {
//				if (in.available() > 0)
//					continue;
//				System.out.println("exit-status: " + channel.getExitStatus());
//			 
//				break;
//			}
//			try {
//				Thread.sleep(1000);
//			} catch (Exception ee) {
//			}
//		}
		
		System.out.println("exit-status: " + channel.getExitStatus());
		 
		channel.disconnect();
		session.disconnect();

 
	
	
	
	
	
 
	
	
	
}



}
