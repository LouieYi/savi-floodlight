package net.floodlightcontroller.savi.module;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.ICMPv6;
import net.floodlightcontroller.packet.IPv6;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;
import net.floodlightcontroller.savi.action.Action;
import net.floodlightcontroller.savi.action.Action.ActionFactory;
import net.floodlightcontroller.savi.binding.Binding;
import net.floodlightcontroller.savi.binding.BindingPool;
import net.floodlightcontroller.savi.binding.BindingStatus;

public class SLAACService extends SAVIBaseService {

	protected static int TIMER_DELAY = 1; // 1s
	protected static int UPDATE_DELAY = 2;
	
	BindingPool<IPv6Address> pool;
	Set<Binding<IPv6Address>> updateQueue;
	
	protected SingletonTask timer;
	@Override
	public void startUpService() {
		// TODO Auto-generated method stub

	}
	protected RoutingAction processICMPv6(SwitchPort switchPort,Ethernet eth){
		IPv6 ipv6 = (IPv6)eth.getPayload();
		ICMPv6 icmpv6 = (ICMPv6)ipv6.getPayload();
		switch(icmpv6.getICMPv6Type()){
		case ICMPv6.NEIGHBOR_ADVERTISEMENT:
			return processNeighborAdvertisement(switchPort, eth);
		case ICMPv6.NEIGHBOR_SOLICITATION:
			return processNeighborSoliciation(switchPort, eth);
			
		case ICMPv6.ROUTER_ADVERTSEMENT:
			return processRouterAdvertisement(switchPort, eth);
			
		case ICMPv6.ROUTER_SOLICITATION:
			return processRouterSolification(switchPort, eth);
			
		}
		return null;
	}
	
	protected boolean isICMPv6(IPv6 ipv6){
		if(ipv6.getNextHeader().equals(IpProtocol.IPv6_ICMP)){
			return true;
		}
		return false;
	}
	
	
	protected RoutingAction processNeighborAdvertisement(SwitchPort switchPort,Ethernet eth){
		IPv6 ipv6 = (IPv6)eth.getPayload();
		ICMPv6 icmpv6 = (ICMPv6)ipv6.getPayload();
		
		MacAddress macAddress = eth.getSourceMACAddress();
		IPv6Address targetAddress = icmpv6.getTargetAddress();
		Binding<IPv6Address> binding = null;
		
		if(pool.isContain(targetAddress)){
			binding = pool.getBinding(targetAddress);
			if(binding.check(macAddress, targetAddress)){
				return RoutingAction.FORWARD_OR_FLOOD;
			}
		}
		return RoutingAction.NONE;
		
	}
	
	protected RoutingAction processNeighborSoliciation(SwitchPort switchPort,Ethernet eth){
		List<Action> actions = new ArrayList<>();
		IPv6 ipv6 = (IPv6)eth.getPayload();
		ICMPv6 icmpv6 = (ICMPv6)ipv6.getPayload();
		
		MacAddress macAddress = eth.getSourceMACAddress();
		IPv6Address targetAddress = icmpv6.getTargetAddress();
		Binding<IPv6Address> binding = null;
		
		if(!pool.isContain(macAddress)){
			pool.addHardwareBinding(macAddress, switchPort);
		}
		actions.add(ActionFactory.getCheckIPv6Binding(switchPort, macAddress, targetAddress));
		if(saviProvider.pushActions(actions)){
			return RoutingAction.FORWARD_OR_FLOOD;
		}
		else if(pool.isContain(targetAddress)){
			actions.clear();
			binding = pool.getBinding(targetAddress);
			if(binding.check(macAddress,targetAddress)){
				actions.add(ActionFactory.getFloodAction(switchPort.getSwitchDPID(), switchPort.getPort(), eth));
				saviProvider.pushActions(actions);
			}
		}
		else{
			actions.clear();
			binding = new Binding<>();
			
			binding.setAddress(targetAddress);
			binding.setMacAddress(macAddress);
			binding.setStatus(BindingStatus.DETECTING);
			binding.setBindingTime();
			pool.addBinding(targetAddress, binding);
			
			updateQueue.add(binding);
			
			actions.add(ActionFactory.getFloodAction(switchPort.getSwitchDPID(), switchPort.getPort(), eth));
			saviProvider.pushActions(actions);
		}
		return RoutingAction.NONE;
	
	}
	
	protected RoutingAction processRouterAdvertisement(SwitchPort switchPort,Ethernet eth){
		return null;
	}
	
	protected RoutingAction processRouterSolification(SwitchPort switchPort,Ethernet eth){
		return null;
	}

	@Override
	public boolean match(Ethernet eth) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public List<Match> getMatches() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public RoutingAction process(SwitchPort switchPort, Ethernet eth) {
		// TODO Auto-generated method stub
		return null;
	}

}
