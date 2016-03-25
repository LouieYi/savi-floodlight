package net.floodlightcontroller.savi.rest;

import java.util.HashMap;
import java.util.Map;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.resource.Post;
import org.restlet.resource.ServerResource;
import org.restlet.routing.Router;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonToken;
import com.fasterxml.jackson.databind.MappingJsonFactory;

import net.floodlightcontroller.restserver.RestletRoutable;

public class SAVIRest extends ServerResource {
	protected static Logger log = LoggerFactory.getLogger(SAVIRest.class);
	
	public static final String CONFIG_DHCP_SERVER_TYPE = "config_server";
	public static final String ADD_SECURITY_PORT_TYPE = "add_security_port";
	public static final String DEL_SECURITY_PORT_TYPE = "del_security_port";
	public static final String GET_BINDING_TYPE = "get_binding";
	
	public static final String SWITCH_DPID = "dpid";
	public static final String PORT_NUM = "port";
	public static final String MAC = "mac";
	public static final String IP = "ip";
	public static final String IPv6 = "ipv6";
	
	public class SAVIRoutable implements RestletRoutable{
		@Override
		public Restlet getRestlet(Context context) {
			// TODO Auto-generated method stub
			Router router = new Router(context);
			router.attach("/config", SAVIRest.class);
			return router;
		}

		@Override
		public String basePath() {
			// TODO Auto-generated method stub
			return "/savi";
		}	
	}
	@SuppressWarnings("deprecation")
	@Post
	public String post(String json){
		Map<String, String> jsonMap = new HashMap<>();
		JsonParser jp;
		MappingJsonFactory f = new MappingJsonFactory();
		try {
			jp = f.createJsonParser(json);
		}
		catch(Exception e){
			e.printStackTrace();
			return "{ERROR}";
		}
		try{
			jp.nextToken();
			if(jp.getCurrentToken() != JsonToken.START_OBJECT){
				return "{}";
			}
			while(jp.nextToken()!=JsonToken.END_OBJECT){
				String name = jp.getCurrentName();
				jp.nextToken();
				jsonMap.put(name, jp.getCurrentName());
			}
		}
		catch(Exception e){
			e.printStackTrace();
		}
		
		return "{OK}";
		
	}
}
