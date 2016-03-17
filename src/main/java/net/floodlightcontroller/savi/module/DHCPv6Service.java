package net.floodlightcontroller.savi.module;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;

import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.DHCPv6;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv6;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;
import net.floodlightcontroller.savi.action.Action;
import net.floodlightcontroller.savi.action.Action.ActionFactory;
import net.floodlightcontroller.savi.binding.Binding;
import net.floodlightcontroller.savi.binding.BindingPool;
import net.floodlightcontroller.savi.binding.BindingStatus;

public class DHCPv6Service extends SAVIBaseService {

	protected BindingPool<IPv6Address> pool;
	protected Map<Integer, Binding<IPv6Address>> confirmQueue;
	@Override
	public void startUpService() {
		// TODO Auto-generated method stub
		pool = new BindingPool<>();
		confirmQueue = new HashMap<>();

	}
	protected RoutingAction processDHCPv6(SwitchPort switchPort,Ethernet eth){
		IPv6 ipv6 = (IPv6)eth.getPayload();
		UDP udp = (UDP)ipv6.getPayload();
		DHCPv6 dhcp = (DHCPv6)udp.getPayload();
		
		MacAddress macAddress = eth.getSourceMACAddress();
		
		if(!pool.isContain(macAddress)){
			pool.addHardwareBinding(macAddress, switchPort);
		}
		
		switch(dhcp.getMsgType()){
		case DHCPv6.SOLICIT:
			return processSolicit(switchPort, eth);
		case DHCPv6.ADVERTISE:
			return processAdvertise(switchPort, eth);
		case DHCPv6.REQUEST:
			return processRequest(switchPort, eth);
		case DHCPv6.REPLY:
			return processReply(switchPort, eth);
			
		case DHCPv6.RENEW:
			break;
		case DHCPv6.CONFIRM:
			return processConfirm(switchPort, eth);
		
		case DHCPv6.DECLINE:
			return processDecline(switchPort, eth);
			
		default:
			log.info("DEFAULT");
		}
		return null;
	}
	protected RoutingAction processSolicit(SwitchPort switchPort,Ethernet eth){
		List<Action> actions = new ArrayList<>();
		actions.add(ActionFactory.getFloodAction(switchPort.getSwitchDPID(), switchPort.getPort(), eth));
		saviProvider.pushActions(actions);
		return RoutingAction.NONE;
	}
	protected RoutingAction processAdvertise(SwitchPort switchPort,Ethernet eth){
		List<Action> actions = new ArrayList<>();
		IPv6 ipv6 = (IPv6)eth.getPayload();
		MacAddress srcMac = eth.getSourceMACAddress();
		IPv6Address ipv6Address = ipv6.getSourceAddress();
		
		if(!pool.isContain(ipv6Address)){
			Binding<IPv6Address> binding = new Binding<>();
			
			binding.setAddress(ipv6Address);
			binding.setMacAddress(srcMac);
			binding.setStatus(BindingStatus.BOUND);
			binding.setAddress(ipv6Address);
			pool.addBinding(ipv6Address, binding);
			
			actions.add(ActionFactory.getBindIPv6Action(binding));
		}
		
		actions.add(ActionFactory.getFloodAction(switchPort.getSwitchDPID(), switchPort.getPort(), eth));
		saviProvider.pushActions(actions);
		return RoutingAction.NONE;
	}
	protected RoutingAction processRequest(SwitchPort switchPort,Ethernet eth){
		List<Action> actions = new ArrayList<>();
		IPv6 ipv6 = (IPv6)eth.getPayload();
		UDP udp = (UDP)ipv6.getPayload();
		DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
		IPv6Address ipv6Address = dhcpv6.getTargetAddress();
		MacAddress mac = eth.getSourceMACAddress();
		Binding<IPv6Address> binding = new Binding<>();
		
		binding.setAddress(ipv6Address);
		binding.setStatus(BindingStatus.REQUESTING);
		binding.setMacAddress(mac);
		binding.setTransactionId(dhcpv6.getTransactionId());
		
		pool.addBinding(ipv6Address, binding);
		
		actions.add(ActionFactory.getFloodAction(switchPort.getSwitchDPID(), switchPort.getPort(), eth));
		saviProvider.pushActions(actions);
		return RoutingAction.NONE;
	}
	
	protected RoutingAction processReply(SwitchPort switchPort,Ethernet eth){
		List<Action> actions = new ArrayList<>();
		IPv6 ipv6 = (IPv6)eth.getPayload();
		UDP udp = (UDP)ipv6.getPayload();
		DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
		IPv6Address ipv6Address = dhcpv6.getTargetAddress();
		MacAddress macAddress = eth.getDestinationMACAddress();
		int id = dhcpv6.getTransactionId();
		
		if(confirmQueue.containsKey(id)){
			Binding<IPv6Address> binding = confirmQueue.get(id);
			binding.setStatus(BindingStatus.BOUND);
			
			actions.add(ActionFactory.getPacketOutAction(eth, pool.getSwitchPort(binding.getMacAddress()), OFPort.CONTROLLER));
			
			confirmQueue.remove(id);
		}
		else if(pool.isContain(ipv6Address)){
			Binding<IPv6Address> binding = pool.getBinding(ipv6Address);
			
			if(binding.getStatus() == BindingStatus.REQUESTING){
				binding.setStatus(BindingStatus.BOUND);
				binding.setLeaseTime(dhcpv6.getValidLifetime());
				binding.setBindingTime();
				
				actions.add(ActionFactory.getBindIPv6Action(binding));
				
			}
			else if(binding.getStatus() == BindingStatus.REBINDING){
				binding.setStatus(BindingStatus.BOUND);
				binding.setLeaseTime(dhcpv6.getValidLifetime());
				binding.setBindingTime();
				
			}
			actions.add(ActionFactory.getPacketOutAction(eth,pool.getSwitchPort(macAddress) , OFPort.CONTROLLER));
		}
		saviProvider.pushActions(actions);
		return RoutingAction.NONE;
	}
	
	protected RoutingAction processRenew(SwitchPort switchPort,Ethernet eth){
		return null;
	}
	
	protected RoutingAction processConfirm(SwitchPort switchPort,Ethernet eth){
		List<Action> actions = new ArrayList<>();
		IPv6 ipv6 = (IPv6)eth.getPayload();
		UDP udp = (UDP)ipv6.getPayload();
		DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
		IPv6Address ipv6Address = dhcpv6.getTargetAddress();
		MacAddress macAddress = eth.getSourceMACAddress();
		
		if(pool.check(ipv6Address, macAddress)){
			Binding<IPv6Address> binding = pool.getBinding(ipv6Address);
			
			binding.setStatus(BindingStatus.CONFIRMING);
			confirmQueue.put(Integer.valueOf(dhcpv6.getTransactionId()), binding);
			
			actions.add(ActionFactory.getPacketOutAction(eth, pool.getSwitchPort(eth.getDestinationMACAddress()), OFPort.CONTROLLER));
			saviProvider.pushActions(actions);
		}
		return RoutingAction.NONE;
	}
	
	protected RoutingAction processDecline(SwitchPort switchPort,Ethernet eth){
		List<Action> actions = new ArrayList<>();
		IPv6 ipv6 = (IPv6)eth.getPayload();
		UDP udp = (UDP)ipv6.getPayload();
		DHCPv6 dhcpv6 = (DHCPv6)udp.getPayload();
		IPv6Address ipv6Address = dhcpv6.getTargetAddress();
		MacAddress macAddress = eth.getDestinationMACAddress();
		
		if(pool.isContain(ipv6Address)){
			pool.delBinding(ipv6Address);
			
			actions.add(ActionFactory.getUnbindIPv6ACtion(ipv6Address, pool.getBinding(ipv6Address)));
			
			actions.add(ActionFactory.getPacketOutAction(eth, pool.getSwitchPort(macAddress), OFPort.CONTROLLER));
			saviProvider.pushActions(actions);
		}
		return RoutingAction.NONE;
		
	}
	
	
	protected boolean isDHCPv6(Ethernet eth){
		if(eth.getEtherType() == EthType.IPv6){
			IPv6 ipv6 = (IPv6)eth.getPayload();
			if(ipv6.getNextHeader().equals(IpProtocol.UDP)){
				UDP udp = (UDP)ipv6.getPayload();
				if(udp.getSourcePort().getPort() == 546 || udp.getDestinationPort().getPort() == 546){
					return true;
				}
			}
		}
		return false;
	}
	@Override
	public boolean match(Ethernet eth) {
		// TODO Auto-generated method stub
		return isDHCPv6(eth);
	}

	@Override
	public List<Match> getMatches() {
		// TODO Auto-generated method stub
		List<Match> array = new ArrayList<>();
		
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP);
		mb.setExact(MatchField.UDP_DST, TransportPort.of(547));
		mb.setExact(MatchField.UDP_SRC, TransportPort.of(546));
		array.add(mb.build());
		
		mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP);
		mb.setExact(MatchField.UDP_DST, TransportPort.of(546));
		mb.setExact(MatchField.UDP_SRC, TransportPort.of(547));
		array.add(mb.build());
		
		return array;
	}

	@Override
	public RoutingAction process(SwitchPort switchPort, Ethernet eth) {
		// TODO Auto-generated method stub
		return processDHCPv6(switchPort, eth);
	}

}