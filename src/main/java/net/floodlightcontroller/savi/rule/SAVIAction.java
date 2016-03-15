package net.floodlightcontroller.savi.rule;

import java.util.ArrayList;
import java.util.List;

import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import net.floodlightcontroller.devicemanager.SwitchPort;

public class SAVIAction {
	public enum SAVIActionType{
		DROP,
		PACKET_OUT,
		PACKET_OUT_MULTI_PORT,
		FLOOD,
		FLOW_MOD
	}
	SAVIActionType 		type;
	Match 				match;
	List<OFAction> 		actions;
	List<SwitchPort>	switchPorts;
	
	public SAVIAction() {
		// TODO Auto-generated constructor stub
		type = null;
		match = null;
		actions = null;
		switchPorts = null;
	}

	public SAVIActionType getType() {
		return type;
	}

	public void setType(SAVIActionType type) {
		this.type = type;
	}

	public Match getMatch() {
		return match;
	}

	public void setMatch(Match match) {
		this.match = match;
	}

	public List<OFAction> getActions() {
		return actions;
	}

	public void setActions(List<OFAction> actions) {
		this.actions = actions;
	}

	public List<SwitchPort> getSwitchPorts() {
		return switchPorts;
	}

	public void setSwitchPorts(List<SwitchPort> switchPorts) {
		this.switchPorts = switchPorts;
	}
	
	public void setSwitchPort(SwitchPort switchPort){
		if(this.switchPorts == null){
			this.switchPorts = new ArrayList<>();
		}
		this.switchPorts.set(0, switchPort);
	}
	
	public SwitchPort getSwitchPort(){
		if(this.switchPorts!=null){
			return this.switchPorts.get(0);
		}
		return null;
	}
	
}
