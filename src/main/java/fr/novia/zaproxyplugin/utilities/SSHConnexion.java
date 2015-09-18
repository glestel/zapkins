package fr.novia.zaproxyplugin.utilities;

import java.io.IOException;
import java.io.InputStream;

import javax.swing.JTextArea;

import com.jcraft.jsch.Channel;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

public class SSHConnexion {
	
	public SSHConnexion(){
		
	}
	
	
public static boolean startZAPDaemon(String HOST, int PORT, String USER, String PASSWORD , String ZAPPATH, JTextArea textAreaLogs){
    	
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
						textAreaLogs.append(new String(tmp, 0, i));
						 
					}
					
					/************************************/
					
					if (channel.isClosed()) {
						if (in.available() > 0)
							continue;
						System.out.println("exit-status: " + channel.getExitStatus());
						System.out.println("Chanel closed");
						textAreaLogs.append("exit-status: " + channel.getExitStatus());
						textAreaLogs.append("Chanel closed");
						break;
					}
					
					/************************************/
					try {
						Thread.sleep(1000);
					} catch (Exception ee) {
					}
			}
			
			System.out.println("exit-status: " + channel.getExitStatus());
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

public static boolean execCommand(String HOST, int PORT, String USER, String PASSWORD , String command,JTextArea textAreaLogs){
	
	JSch jsch = new JSch();
	try {

		Session session = jsch.getSession(USER, HOST, PORT);
		session.setPassword(PASSWORD);
		session.setConfig("StrictHostKeyChecking", "no");
		session.connect(30000); // making a connection with timeout.

		
		Channel channel = session.openChannel("exec");
		// Enable agent-forwarding.
	   // ((ChannelShell)channel).setAgentForwarding(true);
		((ChannelExec) channel).setCommand(command);

		channel.setInputStream(null);
		((ChannelExec) channel).setErrStream(System.err);
		
		
		
		InputStream in = channel.getInputStream();

		channel.connect();

		byte[] tmp = new byte[1024];
		
		while (true) {
			while (in.available() > 0) {
				int i = in.read(tmp, 0, 1024);
				if (i < 0)
					break;
				System.out.print(new String(tmp, 0, i));
				textAreaLogs.append(new String(tmp, 0, i));
				System.out.println("exit-status: " + channel.getExitStatus());
			}
			if (channel.isClosed()) {
				if (in.available() > 0)
					continue;
				System.out.println("exit-status: " + channel.getExitStatus());
				textAreaLogs.append("exit-status: " + channel.getExitStatus());
				break;
			}
			try {
				Thread.sleep(1000);
			} catch (Exception ee) {
			}
		}
		
		System.out.println("exit-status: " + channel.getExitStatus());
		channel.disconnect();
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


}
