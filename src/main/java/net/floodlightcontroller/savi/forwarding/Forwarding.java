package net.floodlightcontroller.savi.forwarding;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFFlowModCommand;
import org.projectfloodlight.openflow.protocol.OFFlowModFlags;
import org.projectfloodlight.openflow.protocol.OFFlowRemoved;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionPushMpls;
import org.projectfloodlight.openflow.protocol.action.OFActionSetField;
import org.projectfloodlight.openflow.protocol.action.OFActionSetMplsTtl;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.protocol.oxm.OFOxms;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.OFVlanVidMatch;
import org.projectfloodlight.openflow.types.U32;
import org.projectfloodlight.openflow.types.U64;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.IOFSwitchListener;
import net.floodlightcontroller.core.PortChangeType;
import net.floodlightcontroller.core.internal.IOFSwitchService;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.debugcounter.IDebugCounterService;
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.IPv6;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;
import net.floodlightcontroller.routing.ForwardingBase;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingService;
import net.floodlightcontroller.routing.Route;
import net.floodlightcontroller.routing.RoutingDecision;
import net.floodlightcontroller.savi.Provider;
import net.floodlightcontroller.savi.forwarding.mpls.MPLSLabelManager;
import net.floodlightcontroller.topology.ITopologyService;
import net.floodlightcontroller.topology.NodePortTuple;
import net.floodlightcontroller.util.FlowModUtils;

public class Forwarding extends ForwardingBase implements IFloodlightModule, IOFMessageListener, IOFSwitchListener {

	/**
	 * 
	 */
	protected MPLSLabelManager coreSwitchLabelManager;
	protected Map<EthType, MPLSLabelManager> edgeSwitchLabelManagers;
	
	/**
	 * 
	 * @param sw
	 * @param fr
	 * @param decision
	 * @param cntx
	 * @return
	 */
	public Command processFlowRemovedMessage(IOFSwitch sw, OFFlowRemoved fr,
			IRoutingDecision decision, FloodlightContext cntx){
		U32 label = fr.getMatch().get(MatchField.MPLS_LABEL);
		if(label == null){
			return Command.CONTINUE;
		}
		SwitchPort switchPort=MPLSLabelManager.getSwitchPort(label.getRaw());
		
		if(switchPort!=null){
			if(coreSwitchLabelManager.isContain(switchPort)){
				coreSwitchLabelManager.delLabel(switchPort);
			}
			else{
				for(MPLSLabelManager m:edgeSwitchLabelManagers.values()){
					if(m.isContain(switchPort)){
						m.delLabel(switchPort);
						break;
					}
				}
			}
			
		}
		
		return Command.CONTINUE;
	}
	
	/**
	 * 
	 * @param sw
	 * @param pi
	 * @param decision
	 * @param cntx
	 * @return
	 */
	@Override
	public Command processPacketInMessage(IOFSwitch sw, OFPacketIn pi,
			IRoutingDecision decision, FloodlightContext cntx) {
		// TODO Auto-generated method stub
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		// We found a routing decision (i.e. Firewall is enabled... it's the only thing that makes RoutingDecisions)
		if (decision != null) {
			if (log.isTraceEnabled()) {
				log.trace("Forwarding decision={} was made for PacketIn={}", decision.getRoutingAction().toString(), pi);
			}

			switch(decision.getRoutingAction()) {
			case NONE:
				// don't do anything
				return Command.CONTINUE;
			case FORWARD_OR_FLOOD:
			case FORWARD:
				doForwardFlow(sw, pi, cntx, false);
				return Command.CONTINUE;
			case MULTICAST:
				// treat as broadcast
				log.info("FLL");
				doFlood(sw, pi, cntx);
				return Command.CONTINUE;
			case DROP:
				doDropFlow(sw, pi, decision, cntx);
				return Command.CONTINUE;
			default:
				log.error("Unexpected decision made for this packet-in={}", pi, decision.getRoutingAction());
				return Command.CONTINUE;
			}
		} else { // No routing decision was found. Forward to destination or flood if bcast or mcast.
			if (log.isTraceEnabled()) {
				log.trace("No decision was made for PacketIn={}, forwarding", pi);
			}

			if (eth.isBroadcast() || eth.isMulticast()) {
				doFlood(sw, pi, cntx);
			} else {
				doForwardFlow(sw, pi, cntx, false);
			}
		}

		return Command.CONTINUE;
	}
	
	/**
	 * 
	 * @param sw
	 * @param msg
	 * @param cntx
	 * @return
	 */
	@Override
	public Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		IRoutingDecision decision = null;
		if (cntx != null) {
			decision = RoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
		}
		switch (msg.getType()) {
		case PACKET_IN:
			return this.processPacketInMessage(sw, (OFPacketIn) msg, decision, cntx);
		case FLOW_REMOVED:
			return this.processFlowRemovedMessage(sw, (OFFlowRemoved)msg, decision, cntx);
		default:
			break;
		}
		return Command.CONTINUE;
	}
	
	@Override
	public boolean pushRoute(Route route, Match match, OFPacketIn pi,
			DatapathId pinSwitch, U64 cookie, FloodlightContext cntx,
			boolean requestFlowRemovedNotification, OFFlowModCommand flowModCommand) {
		
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		MPLSLabelManager edgeSwitchManager = edgeSwitchLabelManagers.get(eth.getEtherType());
		ArrayList<U32> labels = new ArrayList<U32>();
		List<NodePortTuple> switchPortList = route.getPath();
		boolean pushDone = false;
		short ttl = 2;
		int size = switchPortList.size();
		
		for(int index = size - 1;index>0;index-=2){
			DatapathId dpid = switchPortList.get(index).getNodeId();
			IOFSwitch sw = switchService.getSwitch(dpid);
			OFPort outPort = switchPortList.get(index).getPortId();
			SwitchPort switchPort = new SwitchPort(dpid, outPort);
			
			int label = 0;
			if(sw == null){
				break;
			}
			
			if(index == 1){
				OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
				List<OFAction> actions = new ArrayList<OFAction>();
				OFActionPushMpls.Builder apmb = sw.getOFFactory().actions().buildPushMpls();
				OFOxms oxms = sw.getOFFactory().oxms();
				OFActionSetMplsTtl.Builder setMplsTtl = sw.getOFFactory().actions().buildSetMplsTtl();
				OFActionSetField.Builder setMplsLabel = sw.getOFFactory().actions().buildSetField();
				
				for(int i=0;i<labels.size();i++){
					apmb.setEthertype(EthType.MPLS_UNICAST);
					actions.add(apmb.build());
					setMplsLabel.setField(oxms.buildMplsLabel().setValue(labels.get(i)).build());
					actions.add(setMplsLabel.build());
					setMplsTtl.setMplsTtl(ttl++);
					actions.add(setMplsTtl.build());
				}
				
				actions.add(sw.getOFFactory().actions().output(outPort, Integer.MAX_VALUE));
				
				fmb.setActions(actions)
				   .setCookie(cookie)
				   .setMatch(match)
				   .setTableId(Provider.FLOW_TABLE_ID)
				   .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT_CONSTANT)
				   .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT_CONSTANT)
				   .setPriority(FLOWMOD_DEFAULT_PRIORITY)
				   .setBufferId(OFBufferId.NO_BUFFER);
				sw.write(fmb.build());	
				pushDone = true;
			}
			else if(index == size - 1){
				Integer tmp = edgeSwitchManager.getLabel(switchPort);
				
				if(tmp != null){
					label = tmp.intValue();
				}
				else{
					
					label = MPLSLabelManager.allocateNewLabel();
					edgeSwitchManager.addLabel(switchPort, label);
					
					ArrayList<OFAction> actions = new ArrayList<OFAction>();
					actions.add(sw.getOFFactory().actions().popMpls(EthType.IPv4));
					actions.add(sw.getOFFactory().actions().output(outPort, Integer.MAX_VALUE));
					OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
					Set<OFFlowModFlags> sfmf = new HashSet<OFFlowModFlags>();
					sfmf.add(OFFlowModFlags.SEND_FLOW_REM);
					
					fmb.setFlags(sfmf)
					   .setActions(actions)
					   .setTableId(Provider.FLOW_TABLE_ID)
					   .setCookie(cookie)
					   .setMatch(creatematchFromMPLS(sw, label))
					   .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
					   .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
					   .setPriority(FLOWMOD_DEFAULT_PRIORITY)
					   .setBufferId(OFBufferId.NO_BUFFER);
					sw.write(fmb.build());
				}
				
				labels.add(U32.of(label));
				
				pushPacket(sw, eth, OFPort.CONTROLLER, outPort, cntx);
			}
			else{
				Integer tmp = coreSwitchLabelManager.getLabel(switchPort);
				
				if(tmp != null){
					label = tmp.intValue();
				}
				else{
					label = MPLSLabelManager.allocateNewLabel();
					coreSwitchLabelManager.addLabel(switchPort, label);
					
					
					ArrayList<OFAction> actions = new ArrayList<OFAction>();
					actions.add(sw.getOFFactory().actions().popMpls(EthType.MPLS_UNICAST));
					actions.add(sw.getOFFactory().actions().output(outPort, Integer.MAX_VALUE));
					OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd();
					Set<OFFlowModFlags> sfmf = new HashSet<OFFlowModFlags>();
					sfmf.add(OFFlowModFlags.SEND_FLOW_REM);
					
					fmb.setFlags(sfmf)
					   .setTableId(Provider.FLOW_TABLE_ID)
					   .setActions(actions)
					   .setCookie(cookie)
					   .setMatch(creatematchFromMPLS(sw, label))
					   .setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
					   .setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
					   .setPriority(FLOWMOD_DEFAULT_PRIORITY)
					   .setBufferId(OFBufferId.NO_BUFFER);
					sw.write(fmb.build());
				}	
				labels.add(U32.of(label));
			}
		}
		return pushDone;
	}
	
	/**
	 * 
	 * @param sw
	 * @param pi
	 * @param decision
	 * @param cntx
	 */
	protected void doDropFlow(IOFSwitch sw, OFPacketIn pi, IRoutingDecision decision, FloodlightContext cntx) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		Match m = createMatchFromPacket(sw, inPort, cntx);
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd(); // this will be a drop-flow; a flow that will not output to any ports
		List<OFAction> actions = new ArrayList<OFAction>(); // set no action to drop
		fmb.setCookie(ForwardingBase.appCookie)
		.setHardTimeout(FLOWMOD_DEFAULT_HARD_TIMEOUT)
		.setIdleTimeout(FLOWMOD_DEFAULT_IDLE_TIMEOUT)
		.setBufferId(OFBufferId.NO_BUFFER)
		.setMatch(m)
		.setPriority(FLOWMOD_DEFAULT_PRIORITY);
		
		FlowModUtils.setActions(fmb, actions, sw);

		try {
			if (log.isDebugEnabled()) {
				log.debug("write drop flow-mod sw={} match={} flow-mod={}",
						new Object[] { sw, m, fmb.build() });
			}
			boolean dampened = messageDamper.write(sw, fmb.build());
			log.debug("OFMessage dampened: {}", dampened);
		} catch (IOException e) {
			log.error("Failure writing drop flow mod", e);
		}
	}
	/**
	 * 
	 * @param sw
	 * @param pi
	 * @param cntx
	 * @param requestFlowRemovedNotifn
	 */
	protected void doForwardFlow(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx, boolean requestFlowRemovedNotifn) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		IDevice dstDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_DST_DEVICE);
		DatapathId source = sw.getId();
			
		if (dstDevice != null) {
			IDevice srcDevice = IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE);

			if (srcDevice == null) {
				log.error("No device entry found for source device. Is the device manager running? If so, report bug.");
				return;
			}
			
			if (FLOOD_ALL_ARP_PACKETS && 
					IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD).getEtherType() 
					== EthType.ARP) {
				log.debug("ARP flows disabled in Forwarding. Flooding ARP packet");
				doFlood(sw, pi, cntx);
				return;
			}

			/* Validate that the source and destination are not on the same switch port */
			boolean on_same_if = false;
			for (SwitchPort dstDap : dstDevice.getAttachmentPoints()) {
				if (sw.getId().equals(dstDap.getSwitchDPID()) && inPort.equals(dstDap.getPort())) {
					on_same_if = true;
				}
				break;
			}

			if (on_same_if) {
				log.info("Both source and destination are on the same switch/port {}/{}. Action = NOP", sw.toString(), inPort);
				return;
			}
	
			SwitchPort[] dstDaps = dstDevice.getAttachmentPoints();
			SwitchPort dstDap = null;

			/* 
			 * Search for the true attachment point. The true AP is
			 * not an endpoint of a link. It is a switch port w/o an
			 * associated link. Note this does not necessarily hold
			 * true for devices that 'live' between OpenFlow islands.
			 * 
			 * TODO Account for the case where a device is actually
			 * attached between islands (possibly on a non-OF switch
			 * in between two OpenFlow switches).
			 */
			for (SwitchPort ap : dstDaps) {
				if (topologyService.isEdge(ap.getSwitchDPID(), ap.getPort())) {
					dstDap = ap;
					break;
				}
			}	

			/* 
			 * This should only happen (perhaps) when the controller is
			 * actively learning a new topology and hasn't discovered
			 * all links yet, or a switch was in standalone mode and the
			 * packet in question was captured in flight on the dst point
			 * of a link.
			 */
			if (dstDap == null) {
				log.warn("Could not locate edge attachment point for device {}. Flooding packet");
				doFlood(sw, pi, cntx);
				return; 
			}
			
			/* It's possible that we learned packed destination while it was in flight */
			if (!topologyService.isEdge(source, inPort)) {	
				log.debug("Packet destination is known, but packet was not received on an edge port (rx on {}/{}). Flooding packet", source, inPort);
				doFlood(sw, pi, cntx);
				return; 
			}				
			
			Route route = routingEngineService.getRoute(source, 
					inPort,
					dstDap.getSwitchDPID(),
					dstDap.getPort(), U64.of(0)); //cookie = 0, i.e., default route

			Match m = createMatchFromPacket(sw, inPort, cntx);
			
			if (route != null) {
				log.debug("pushRoute inPort={} route={} " +
						"destination={}:{}",
						new Object[] { inPort, route,
						dstDap.getSwitchDPID(),
						dstDap.getPort()});


				log.debug("Cretaing flow rules on the route, match rule: {}", m);
				pushRoute(route, m, pi, sw.getId(), ForwardingBase.appCookie, 
						cntx, requestFlowRemovedNotifn,
						OFFlowModCommand.ADD);	
			} else {
				/* Route traverses no links --> src/dst devices on same switch */
				log.debug("Could not compute route. Devices should be on same switch src={} and dst={}", srcDevice, dstDevice);
				Route r = new Route(srcDevice.getAttachmentPoints()[0].getSwitchDPID(), dstDevice.getAttachmentPoints()[0].getSwitchDPID());
				List<NodePortTuple> path = new ArrayList<NodePortTuple>(2);
				path.add(new NodePortTuple(srcDevice.getAttachmentPoints()[0].getSwitchDPID(),
						srcDevice.getAttachmentPoints()[0].getPort()));
				path.add(new NodePortTuple(dstDevice.getAttachmentPoints()[0].getSwitchDPID(),
						dstDevice.getAttachmentPoints()[0].getPort()));
				r.setPath(path);
				pushRoute(r, m, pi, sw.getId(), ForwardingBase.appCookie,
						cntx, requestFlowRemovedNotifn,
						OFFlowModCommand.ADD);
			}
		} else {
			log.debug("Destination unknown. Flooding packet");
			doFlood(sw, pi, cntx);
		}
	}
	
	/**
	 * 
	 * @param sw
	 * @param label
	 * @return
	 */
	protected Match creatematchFromMPLS(IOFSwitch sw, int label){
		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.ETH_TYPE, EthType.MPLS_UNICAST);
		mb.setExact(MatchField.MPLS_LABEL, U32.of(label));
		return mb.build();
		
	}
	/**
	 * 
	 * @param sw
	 * @param inPort
	 * @param cntx
	 * @return
	 */
	protected Match createMatchFromPacket(IOFSwitch sw, OFPort inPort, FloodlightContext cntx) {
		// The packet in match will only contain the port number.
		// We need to add in specifics for the hosts we're routing between.
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		VlanVid vlan = VlanVid.ofVlan(eth.getVlanID());
		MacAddress srcMac = eth.getSourceMACAddress();
		MacAddress dstMac = eth.getDestinationMACAddress();

		Match.Builder mb = sw.getOFFactory().buildMatch();
		mb.setExact(MatchField.IN_PORT, inPort);

		if (FLOWMOD_DEFAULT_MATCH_MAC) {
			mb.setExact(MatchField.ETH_SRC, srcMac)
			.setExact(MatchField.ETH_DST, dstMac);
		}

		if (FLOWMOD_DEFAULT_MATCH_VLAN) {
			if (!vlan.equals(VlanVid.ZERO)) {
				mb.setExact(MatchField.VLAN_VID, OFVlanVidMatch.ofVlanVid(vlan));
			}
		}

		// TODO Detect switch type and match to create hardware-implemented flow
		if (eth.getEtherType() == EthType.IPv4) { /* shallow check for equality is okay for EthType */
			IPv4 ip = (IPv4) eth.getPayload();
			IPv4Address srcIp = ip.getSourceAddress();
			IPv4Address dstIp = ip.getDestinationAddress();
			
			if (FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv4)
				.setExact(MatchField.IPV4_SRC, srcIp)
				.setExact(MatchField.IPV4_DST, dstIp);
			}

			if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
				/*
				 * Take care of the ethertype if not included earlier,
				 * since it's a prerequisite for transport ports.
				 */
				if (!FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
					mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
				}
				
				if (ip.getProtocol().equals(IpProtocol.TCP)) {
					TCP tcp = (TCP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
					.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
					.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
				} else if (ip.getProtocol().equals(IpProtocol.UDP)) {
					UDP udp = (UDP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
					.setExact(MatchField.UDP_SRC, udp.getSourcePort())
					.setExact(MatchField.UDP_DST, udp.getDestinationPort());
				}
			}
		} else if (eth.getEtherType() == EthType.ARP) { /* shallow check for equality is okay for EthType */
			mb.setExact(MatchField.ETH_TYPE, EthType.ARP);
		} else if (eth.getEtherType() == EthType.IPv6) {
			IPv6 ip = (IPv6) eth.getPayload();
			IPv6Address srcIp = ip.getSourceAddress();
			IPv6Address dstIp = ip.getDestinationAddress();
			
			if (FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
				mb.setExact(MatchField.ETH_TYPE, EthType.IPv6)
				.setExact(MatchField.IPV6_SRC, srcIp)
				.setExact(MatchField.IPV6_DST, dstIp);
			}

			if (FLOWMOD_DEFAULT_MATCH_TRANSPORT) {
				/*
				 * Take care of the ethertype if not included earlier,
				 * since it's a prerequisite for transport ports.
				 */
				if (!FLOWMOD_DEFAULT_MATCH_IP_ADDR) {
					mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
				}
				
				if (ip.getNextHeader().equals(IpProtocol.TCP)) {
					TCP tcp = (TCP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP)
					.setExact(MatchField.TCP_SRC, tcp.getSourcePort())
					.setExact(MatchField.TCP_DST, tcp.getDestinationPort());
				} else if (ip.getNextHeader().equals(IpProtocol.UDP)) {
					UDP udp = (UDP) ip.getPayload();
					mb.setExact(MatchField.IP_PROTO, IpProtocol.UDP)
					.setExact(MatchField.UDP_SRC, udp.getSourcePort())
					.setExact(MatchField.UDP_DST, udp.getDestinationPort());
				}
			}
		}
		return mb.build();
	}
	protected void doPacketOut(SwitchPort switchPort, byte[] data) {
		
		IOFSwitch sw = switchService.getActiveSwitch(switchPort.getSwitchDPID());
		OFPort port = switchPort.getPort();
		
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
		
		pob.setActions(actions)
		   .setBufferId(OFBufferId.NO_BUFFER)
		   .setData(data)
		   .setInPort(OFPort.CONTROLLER);
		
		sw.write(pob.build());
	
	}
	/**
	 * Creates a OFPacketOut with the OFPacketIn data that is flooded on all ports unless
	 * the port is blocked, in which case the packet will be dropped.
	 * @param sw The switch that receives the OFPacketIn
	 * @param pi The OFPacketIn that came to the switch
	 * @param cntx The FloodlightContext associated with this OFPacketIn
	 */
	protected void doFlood(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort() : pi.getMatch().get(MatchField.IN_PORT));
		// Set Action to flood
		SwitchPort inSwitchPort = new SwitchPort(sw.getId(),inPort);
		Collection<? extends IDevice> tmp = deviceManagerService.getAllDevices();
		for (IDevice d : tmp) {
			SwitchPort[] switchPorts = d.getAttachmentPoints();
			for (SwitchPort switchPort : switchPorts) {
				if (!switchPort.equals(inSwitchPort)) {
					doPacketOut(switchPort, pi.getData());
				}
			}
		}
	}
	/**
	 * 
	 * @return
	 */
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}
	/**
	 * 
	 * @return
	 */
	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}
	
	
	/**
	 * 
	 * @return
	 */

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		
		l.add(IFloodlightProviderService.class);
		l.add(IDeviceService.class);
		l.add(IRoutingService.class);
		l.add(ITopologyService.class);
		l.add(IDebugCounterService.class);
		
		return l;
	}

	/**
	 * 
	 * @param context
	 * @throws FloodlightModuleException
	 */
	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// Initialize ForwardingBase members 
		super.init();
		
		this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		this.switchService = context.getServiceImpl(IOFSwitchService.class);
		this.deviceManagerService = context.getServiceImpl(IDeviceService.class);
		this.routingEngineService = context.getServiceImpl(IRoutingService.class);
		this.topologyService = context.getServiceImpl(ITopologyService.class);
		
		this.coreSwitchLabelManager = new MPLSLabelManager();
		this.edgeSwitchLabelManagers = new HashMap<>();
		
		this.edgeSwitchLabelManagers.put(EthType.ARP, new MPLSLabelManager());
		this.edgeSwitchLabelManagers.put(EthType.IPv4, new MPLSLabelManager());
		this.edgeSwitchLabelManagers.put(EthType.IPv6, new MPLSLabelManager());
		
	}
	
	/**
	 * 
	 * @param context
	 * @throws FloodlightModuleException
	 */
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		super.startUp();
		
		// Add OpenFlow message listener
		this.floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		this.floodlightProviderService.addOFMessageListener(OFType.FLOW_REMOVED, this);
		
		// Add switch service listener
		this.switchService.addOFSwitchListener(this);
	}

	/**
	 * 
	 * @param switchId
	 */
	
	@Override
	public void switchAdded(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	/**
	 * 
	 * @param switchId
	 */
	@Override
	public void switchRemoved(DatapathId switchId) {
		// TODO Auto-generated method stub
		coreSwitchLabelManager.delSwitch(switchId);;
		for(MPLSLabelManager m:edgeSwitchLabelManagers.values()){
			m.delSwitch(switchId);
		}
	}

	/**
	 * 
	 * @param switchId
	 */
	@Override
	public void switchActivated(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	/**
	 * 
	 * @param switchId
	 * @param port
	 * @param type
	 */
	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
		// TODO Auto-generated method stub
		
	}

	/**
	 * 
	 * @param switchId
	 */
	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}
	
	/**
	 * 
	 * @param sw
	 * @param eth
	 * @param inPort
	 * @param outPorts
	 * @param cntx
	 */
	protected void pushPacket(IOFSwitch sw, Ethernet eth, OFPort inPort, Set<OFPort> outPorts, FloodlightContext cntx){
		List<OFAction> actions = new ArrayList<>();
		
		Iterator<OFPort> p = outPorts.iterator();
		while(p.hasNext()){
			actions.add(sw.getOFFactory().actions().output(p.next(), Integer.MAX_VALUE));
		}
		
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		pob.setActions(actions);

		pob.setBufferId(OFBufferId.NO_BUFFER);
		pob.setInPort(inPort);

		pob.setData(eth.serialize());

		try {
			if (log.isTraceEnabled()) {
				log.trace("write broadcast packet on switch-id={} " +
						"interfaces={} packet-out={}",
						new Object[] {sw.getId(), outPorts, pob.build()});
			}
			messageDamper.write(sw, pob.build());

		} catch (IOException e) {
			log.error("Failure writing packet out", e);
		}
		
	}
	/**
	 * Pushes a packet-out to a switch. The assumption here is that
	 * the packet-in was also generated from the same switch. Thus, if the input
	 * port of the packet-in and the outport are the same, the function will not
	 * push the packet-out.
	 * @param sw switch that generated the packet-in, and from which packet-out is sent
	 * @param pi packet-in
	 * @param outport output port
	 * @param useBufferedPacket use the packet buffered at the switch, if possible
	 * @param cntx context of the packet
	 */
	protected void pushPacket(IOFSwitch sw, Ethernet eth, OFPort inPort, OFPort outPort, FloodlightContext cntx) {
		if (eth == null || sw == null) {
			return;
		}
		// The assumption here is (sw) is the switch that generated the
		// packet-in. If the input port is the same as output port, then
		// the packet-out should be ignored.

		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		List<OFAction> actions = new ArrayList<OFAction>();
		actions.add(sw.getOFFactory().actions().output(outPort, Integer.MAX_VALUE));
		
		pob.setActions(actions)
		   .setBufferId(OFBufferId.NO_BUFFER)
		   .setData(eth.serialize())
		   .setInPort(inPort);
		
		try {
			messageDamper.write(sw, pob.build());
		} catch (IOException e) {
			log.error("Failure writing packet out", e);
		}
	}
}
