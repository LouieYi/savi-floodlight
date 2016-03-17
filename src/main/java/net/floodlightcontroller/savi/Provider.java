package net.floodlightcontroller.savi;

import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFactories;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFPortDesc;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.OFVersion;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.DatapathId;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
import net.floodlightcontroller.devicemanager.IDevice;
import net.floodlightcontroller.devicemanager.IDeviceService;
import net.floodlightcontroller.devicemanager.SwitchPort;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.routing.IRoutingDecision;
import net.floodlightcontroller.routing.IRoutingDecision.RoutingAction;
import net.floodlightcontroller.routing.RoutingDecision;
import net.floodlightcontroller.savi.action.Action;
import net.floodlightcontroller.savi.action.BindIPv4Action;
import net.floodlightcontroller.savi.action.BindIPv6Action;
import net.floodlightcontroller.savi.action.CheckIPv4BindingAction;
import net.floodlightcontroller.savi.action.CheckIPv6BindingAction;
import net.floodlightcontroller.savi.action.FloodAction;
import net.floodlightcontroller.savi.action.PacketOutAction;
import net.floodlightcontroller.savi.action.UnbindIPv4Action;
import net.floodlightcontroller.savi.action.UnbindIPv6Action;
import net.floodlightcontroller.savi.action.Action.ActionFactory;
import net.floodlightcontroller.savi.binding.Binding;
import net.floodlightcontroller.savi.service.SAVIProviderService;
import net.floodlightcontroller.savi.service.SAVIService;
import net.floodlightcontroller.topology.ITopologyService;

public class Provider implements IFloodlightModule,
IOFSwitchListener, IOFMessageListener, SAVIProviderService {
	
	static final int PROTOCOL_LAYER_PRIORITY = 1;
	static final int SERVICE_LAYER_PRIORITY = 2;
	static final int BINDING_LAYER_PRIORITY = 3;
	static final int EXTENSION_LAYER_PRIORITY = 4;
	
	static final Logger log = LoggerFactory.getLogger(SAVIProviderService.class);
	
	protected IFloodlightProviderService floodlightProvider;
	protected IOFSwitchService switchService;
	protected IDeviceService deviceService;
	protected ITopologyService topologyService;
	
	private List<SAVIService> saviServices;
	private BindingManager manager;
	
	private List<Match> serviceRules;
	private List<Match> protocolRules;
	
	
	private void processPacketIn(IOFSwitch sw, OFPacketIn pi, FloodlightContext cntx) {
		OFPort inPort = (pi.getVersion().compareTo(OFVersion.OF_12) < 0 ? pi.getInPort()
				: pi.getMatch().get(MatchField.IN_PORT));
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD);
		IRoutingDecision decision = IRoutingDecision.rtStore.get(cntx, IRoutingDecision.CONTEXT_DECISION);
		SwitchPort switchPort = new SwitchPort(sw.getId(), inPort);
		
		RoutingAction routingAction = null;
		
		if (decision == null) {
			decision = new RoutingDecision(sw.getId(), inPort,
					IDeviceService.fcStore.get(cntx, IDeviceService.CONTEXT_SRC_DEVICE), RoutingAction.FORWARD);
		}
		for (SAVIService s : saviServices) {
			if (s.match(eth)) {
				routingAction = s.process(switchPort, eth);
				break;
			}
		}
		
		if(routingAction != null)
		{
			decision.setRoutingAction(routingAction);
		}
		decision.addToContext(cntx);
	}
	
	
	@Override
	public void addSAVIService(SAVIService service) {
		// TODO Auto-generated method stub
		saviServices.add(service);
		serviceRules.addAll(service.getMatches());
	}
	
	@Override
	public boolean pushActions(List<Action> actions) {
		// TODO Auto-generated method stub
		
		for(Action action:actions){
			switch(action.getType()){
			case FLOOD:
				doFlood((FloodAction)action);
				break;
			case PACKET_OUT:
			case PACKET_OUT_MULTI_PORT:
				doPacketOut((PacketOutAction)action);
				break;
			case BIND_IPv4:
				doBindIPv4((BindIPv4Action)action);
				break;
			case BIND_IPv6:
				doBindIPv6((BindIPv6Action)action);
				break;
			case UNBIND_IPv4:
				doUnbindIPv4((UnbindIPv4Action)action);
				break;
			case UNBIND_IPv6:
				doUnbindIPv6((UnbindIPv6Action)action);
				break;
			case CHECK_IPv4_BINDING:
				return doCheckIPv4BInding((CheckIPv4BindingAction)action);
			case CHECK_IPv6_BINDING:
				return doCheckIPv6Binding((CheckIPv6BindingAction)action);
			default:
				break;
			}
		}
		return true;
	}
	
	
	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "savi";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;//(type.equals(OFType.PACKET_IN) && (name.equals("topology") || name.equals("devicemanager")));
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;//type.equals(OFType.PACKET_IN) || name.equals("forwarding");
	}

	@Override
	public Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
		// TODO Auto-generated method stub
		
		switch (msg.getType()) {
		case PACKET_IN:
			processPacketIn(sw, (OFPacketIn) msg, cntx);
			return Command.CONTINUE;
		case ERROR:
			log.info("ERROR");
		default:
			break;
		}
		
		return Command.CONTINUE;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> services = new ArrayList<Class<? extends IFloodlightService>>();
		services.add(SAVIProviderService.class);
		return services;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		Map<Class<? extends IFloodlightService>, IFloodlightService> serviceImpls = new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		serviceImpls.put(SAVIProviderService.class, this);
		return serviceImpls;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> dependencies = new ArrayList<Class<? extends IFloodlightService>>();
		dependencies.add(IFloodlightProviderService.class);
		dependencies.add(IOFSwitchService.class);
		dependencies.add(IDeviceService.class);
		dependencies.add(ITopologyService.class);
		return dependencies;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider 	= context.getServiceImpl(IFloodlightProviderService.class);
		switchService 	   	= context.getServiceImpl(IOFSwitchService.class);
		deviceService 	   	= context.getServiceImpl(IDeviceService.class);
		topologyService 	= context.getServiceImpl(ITopologyService.class);
		
		saviServices 		= new ArrayList<>();
		manager 			= new BindingManager();
		
		serviceRules		= new ArrayList<>();
		protocolRules		= new ArrayList<>();
		
		Match.Builder mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv6);
		protocolRules.add(mb.build());
		
		mb = OFFactories.getFactory(OFVersion.OF_13).buildMatch();
		mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
		protocolRules.add(mb.build());
		
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProvider.addOFMessageListener(OFType.ERROR, this);
		switchService.addOFSwitchListener(this);
	}

	@Override
	public void switchAdded(DatapathId switchId) {
		// TODO Auto-generated method stub
		manager.addSwitch(switchId);

	}

	@Override
	public void switchRemoved(DatapathId switchId) {
		// TODO Auto-generated method stub
		manager.removeSwitch(switchId);
		List<Action> actions = new ArrayList<>();
		actions.add(ActionFactory.getClearSwitchBindingAction(switchId));
		for(SAVIService s:saviServices){
			s.pushActins(actions);
		}
	}

	@Override
	public void switchActivated(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchPortChanged(DatapathId switchId, OFPortDesc port, PortChangeType type) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void switchChanged(DatapathId switchId) {
		// TODO Auto-generated method stub
		
	}
	
	
	protected void doFlood(FloodAction action){
		SwitchPort inSwitchPort = new SwitchPort(action.getSwitchId(), action.getInPort());
		byte[] data = action.getEthernet().serialize();
		doFlood(inSwitchPort, data);
	}
	
	protected void doFlood(SwitchPort inSwitchPort, byte[] data){
		Collection<? extends IDevice> tmp = deviceService.getAllDevices();
		for (IDevice d : tmp) {
			SwitchPort[] switchPorts = d.getAttachmentPoints();
			for (SwitchPort switchPort : switchPorts) {
				if (!switchPort.equals(inSwitchPort)) {
					doPacketOut(switchPort, data);
				}
			}
		}
	}
	
	protected void doPacketOut(PacketOutAction action) {
		
		doPacketOut(action.getSwitchId(),
					action.getInPort(),
					action.getOutPorts(),
					action.getEthernet().serialize());
	
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
	
	protected void doPacketOut(DatapathId switchId, OFPort inPort, List<OFPort> outPorts, byte[] data) {
		
		IOFSwitch sw = switchService.getActiveSwitch(switchId);
		
		OFPacketOut.Builder pob = sw.getOFFactory().buildPacketOut();
		
		List<OFAction> actions = new ArrayList<OFAction>();
		for(OFPort port:outPorts) {
			actions.add(sw.getOFFactory().actions().output(port, Integer.MAX_VALUE));
		}
		
		pob.setActions(actions)
		   .setBufferId(OFBufferId.NO_BUFFER)
		   .setData(data)
		   .setInPort(inPort);
		
		sw.write(pob.build());
	}
	
	protected void doBindIPv4(BindIPv4Action action){
		Binding<?> binding = action.getBinding();
		log.info("BIND "+binding.getAddress());
		manager.addBinding(binding);
		
	}
	
	protected void doBindIPv6(BindIPv6Action action){
		Binding<?> binding = action.getBinding();
		log.info("BIND "+binding.getAddress().toString());
		manager.addBinding(binding);
	}
	
	protected void doUnbindIPv4(UnbindIPv4Action action) {
		manager.delBinding(action.getIpv4Address());
	}
	
	protected void doUnbindIPv6(UnbindIPv6Action action) {
		manager.delBinding(action.getIPv6Address());
	}
	
	protected boolean doCheckIPv4BInding(CheckIPv4BindingAction action){
		return manager.check(action.getSwitchPort(), action.getMacAddress(), action.getIPv4Address());
	}
	protected boolean doCheckIPv6Binding(CheckIPv6BindingAction action) {
		return manager.check(action.getSwitchPort(), action.getMacAddress(), action.getIPv6Address());
	}
}
