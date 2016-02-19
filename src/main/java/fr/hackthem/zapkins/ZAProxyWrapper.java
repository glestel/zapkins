package fr.hackthem.zapkins;

import hudson.Extension;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.tasks.BuildWrapper;
import hudson.tasks.BuildWrapperDescriptor;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.export.ExportedBean;
import org.zaproxy.clientapi.core.ClientApiException;

import fr.hackthem.zapkins.api.CustomZapClientApi;

import java.io.IOException;
import java.io.Serializable;
import java.util.Map;

@ExportedBean
public class ZAProxyWrapper extends BuildWrapper implements Serializable {
	

	/**
	 * 
	 */
	private static final long serialVersionUID = -5641693402522157794L;
	private final ZAProxy zaproxy;
//    private String zapProxyHost;
//   // private  int zapProxyPort=8080;
//    private String protocol;
//    private  String zapProxyKey; 
//    private  boolean debugMod;

    @DataBoundConstructor
    public ZAProxyWrapper(  ZAProxy zaproxy) {
    	
    	this.zaproxy=zaproxy;
    	
    
//    	this.protocol=ZAProxyBuilder.DESCRIPTOR.getDefaultProtocol();
//    	this.zapProxyHost = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultHost();	    		 
//    	this.zapProxyKey = ZAProxyBuilder.DESCRIPTOR.getZapProxyDefaultApiKey();
//        this.debugMod=ZAProxyBuilder.DESCRIPTOR.isDebugMod(); 
//        
//       
//        this.zaproxy.setProtocol(protocol);
//        this.zaproxy.setZapProxyHost(zapProxyHost);
//       // this.zaproxy.setZapProxyPort(zapProxyPort);
//        this.zaproxy.setZapProxyKey(zapProxyKey);
//        this.zaproxy.setDebugMod(debugMod);
       
    }
    
    public ZAProxy getZaproxy() {
        return zaproxy;
    }
 
//
//    public String getProtocol() {
//  		return protocol;
//  	}
//
//    public String getZapProxyHost() {
//        return zapProxyHost;
//    }
//
//    public int getZapProxyPort() {
//        return zapProxyPort;
//    }
//    
//    public String getZapProxyKey(){
//    	return zapProxyKey;
//    }  
//
//	public boolean isDebugMod() {
//		return debugMod;
//	}


	

    @Override
    public Environment setUp(AbstractBuild build, Launcher launcher, BuildListener listener) throws IOException, InterruptedException {
        //final ClientApi zapClient = 
    	//final CustomZapClientApi zapClientAPI = new CustomZapClientApi(protocol,zapProxyHost, zapProxyPort, zapProxyKey, listener,debugMod);	 
    	final CustomZapClientApi zapClientAPI=zaproxy.executeZAP( build, launcher,listener)  ;
        
        	 
		 
        return new Environment() {

            @Override
            public void buildEnvVars(Map<String, String> env) {
 
            }

            @Override
            public boolean tearDown(AbstractBuild build, BuildListener listener) {
                try {
                    zaproxy.stopZAP(zapClientAPI, listener);
                } catch (ClientApiException e) {
                    listener.error(ExceptionUtils.getStackTrace(e));
                    return false;
                }
                return true;
            }
        };

    }

    @Extension
    public static final class DescriptorImpl extends BuildWrapperDescriptor {

        public DescriptorImpl() {
            super(ZAProxyWrapper.class);
            load();
        }

        @Override
        public String getDisplayName() {
            return "Start ZAProxy";
        }

        @Override
        public boolean isApplicable(AbstractProject<?, ?> item) {
            return true;
        }

    }

}