package net.floodlightcontroller.savi.rest;

import org.restlet.Context;
import org.restlet.Restlet;
import org.restlet.resource.Directory;
import org.restlet.routing.Router;

import net.floodlightcontroller.restserver.RestletRoutable;

public class SAVIRestRoute implements RestletRoutable{

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
