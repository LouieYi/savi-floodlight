package net.floodlightcontroller.savi.rule;

import java.util.ArrayList;
import java.util.List;

import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;

import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;
import net.floodlightcontroller.savi.rule.SAVIAction.SAVIActionType;

public class SAVIRule {
	public static final RoutingAction DEFAULT_ROUTING_ACTION = RoutingAction.FORWARD;
	
	RoutingAction routingAction;
	List<SAVIAction> saviActions;
	
	public SAVIRule(){
		routingAction = DEFAULT_ROUTING_ACTION;
		saviActions = new ArrayList<>();
	}

	public RoutingAction getRoutingAction() {
		return routingAction;
	}

	public void setRoutingAction(RoutingAction routingAction) {
		this.routingAction = routingAction;
	}
	
	public void addSAVIAction(SAVIAction action){
		this.saviActions.add(action);
	}
	
	public List<SAVIAction> getSAVIActions(){
		return this.saviActions;
	}
	public void addFloodlAction(){
		SAVIAction action = new SAVIAction();
		action.setType(SAVIActionType.FLOOD);
		this.saviActions.add(action);
	}
	public void addPacketOutAction(SwitchPort switchPort){
		SAVIAction action = new SAVIAction();
		action.setType(SAVIActionType.PACKET_OUT);
		action.setSwitchPort(switchPort);
		this.saviActions.add(action);
	}
	public void addPacketOutMultiPortAction(List<SwitchPort> switchPorts){
		SAVIAction action = new SAVIAction();
		action.setType(SAVIActionType.PACKET_OUT_MULTI_PORT);
		action.setSwitchPorts(switchPorts);
		this.saviActions.add(action);
	}
	public void addFlowModAction(SwitchPort switchPort, Match match, List<OFAction> actions){
		SAVIAction action = new SAVIAction();
		action.setType(SAVIActionType.FLOW_MOD);
		action.setSwitchPort(switchPort);
		action.setMatch(match);
		action.setActions(actions);
		this.saviActions.add(action);
	}
	public void addDropAction(SwitchPort switchPort, Match match){
		SAVIAction action = new SAVIAction();
		action.setType(SAVIActionType.DROP);
		action.setSwitchPort(switchPort);
		action.setMatch(match);
		this.saviActions.add(action);
	}
}
