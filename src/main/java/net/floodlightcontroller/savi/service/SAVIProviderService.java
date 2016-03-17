package net.floodlightcontroller.savi.service;

import java.util.List;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.savi.action.Action;

public interface SAVIProviderService extends IFloodlightService {
	
	public void addSAVIService(SAVIService service);
	public boolean pushActions(List<Action> actions);
	
}
