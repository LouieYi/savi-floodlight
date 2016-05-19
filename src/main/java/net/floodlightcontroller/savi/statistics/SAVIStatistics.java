package net.floodlightcontroller.savi.statistics;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumSet;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.SortedSet;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFPacketOut;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IFloodlightProviderService;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;
import net.floodlightcontroller.core.util.AppCookie;
import net.floodlightcontroller.core.util.SingletonTask;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.threadpool.IThreadPoolService;
import net.floodlightcontroller.topology.ITopologyService;

public class SAVIStatistics implements IFloodlightModule, IOFMessageListener, ISAVIStatistics {
	
	protected static Logger log = LoggerFactory.getLogger(SAVIStatistics.class);
	protected static final int OFMESSAGE_DAMPER_CAPACITY = 10000; // TODO: find sweet spot
	protected static final int OFMESSAGE_DAMPER_TIMEOUT = 250; // ms
	protected static final int UPDATE_TASK_INTERVAL = 100 ; // ms
	protected static final int PRINT_INTERVAL = 20;
	
	protected static Map<OFType,String> RECORD_TYPE_SET;
	public static final int SYNFLOW_STATISTICS_APP_ID = 200; 
	
	static {
		RECORD_TYPE_SET = new HashMap<>();
		RECORD_TYPE_SET.put(OFType.FLOW_MOD,"FLOW_MOD");
		RECORD_TYPE_SET.put(OFType.PACKET_IN,"PACKET_IN");
		RECORD_TYPE_SET.put(OFType.PACKET_OUT, "PACKET_OUT");
		RECORD_TYPE_SET.put(OFType.FLOW_REMOVED,"FLOW_REMOVED");
		
		AppCookie.registerApp(SYNFLOW_STATISTICS_APP_ID, "synflow-statistics");
	}
	
	protected Map<OFType, ReferenceInterger> collector;
	protected Queue<OFMessage> updateQueue; 
	
	protected IFloodlightProviderService floodlightProviderService;
	protected IThreadPoolService threadPoolService;
	protected ITopologyService topologyService;

	protected SingletonTask updateTask;
	protected boolean enableAutocalculate = true;
	protected int printId = 0;
	
	
	public class ReferenceInterger {
		int average;
		int sum;
		
		public ReferenceInterger(){
			average = 0;
			sum = 0;
		}
		
		public int getAverage() {
			return average;
			
		}
		
		public int getSum() {
			return sum;
		}
		
		public void clear() {
			average = 0;
		}
		
		public void plusOne() {
			sum += 1;
			average += 1;
		}
	}
	
	@Override
	public void write(IOFSwitch sw, OFMessage msg) {
		// TODO Auto-generated method stub
		if(this.enableAutocalculate) {
			updateQueue.add(msg);
		}
			
	}
	
	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(ISAVIStatistics.class);
		return l;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		Map<Class<? extends IFloodlightService>, IFloodlightService> m =
				new HashMap<Class<? extends IFloodlightService>, IFloodlightService>();
		// We are the class that implements the service
		m.put(ISAVIStatistics.class, this);
		return m;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		// TODO Auto-generated method stub
		Collection<Class<? extends IFloodlightService>> l =
				new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		l.add(IThreadPoolService.class);
		l.add(ITopologyService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		this.floodlightProviderService = context.getServiceImpl(IFloodlightProviderService.class);
		this.threadPoolService = context.getServiceImpl(IThreadPoolService.class);
		this.topologyService = context.getServiceImpl(ITopologyService.class);
		
		this.collector = new ConcurrentHashMap<>();
		this.updateQueue = new ConcurrentLinkedQueue<>();
		
		for(OFType type:RECORD_TYPE_SET.keySet()) {
			this.collector.put(type, new ReferenceInterger());
		}
	}

	private void print(int id,OFType type, ReferenceInterger i){
		log.info("STATISTICS "+id+" "+RECORD_TYPE_SET.get(type)+" "+i.getAverage()+" "+i.getSum());
	}
	
	private boolean filter(IOFSwitch sw,OFMessage msg){
		if(msg.getType() == OFType.PACKET_OUT) {
			OFPacketOut po = (OFPacketOut) msg;
			Ethernet eth = new Ethernet();
			eth.deserialize(po.getData(), 0, po.getData().length);
            if(eth.getEtherType() == EthType.MPLS_UNICAST){
                return true;
            }
            if(eth.getEtherType() != EthType.IPv4) {
				return false;
			}
		}
		else if(msg.getType() == OFType.PACKET_IN) {
			OFPacketIn pi = (OFPacketIn)msg;
			Ethernet eth = new Ethernet();
			eth.deserialize(pi.getData(), 0, pi.getData().length);
			OFPort inPort = pi.getMatch().get(MatchField.IN_PORT);
			if (eth.getEtherType() == EthType.IPv4 || eth.getEtherType() == EthType.MPLS_UNICAST) {
				return true;
			}
			else {
				return false;
			}
		
		}
		return true;
	}
	
	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		// TODO Auto-generated method stub
		floodlightProviderService.addOFMessageListener(OFType.PACKET_IN, this);
		floodlightProviderService.addOFMessageListener(OFType.FLOW_REMOVED, this);	
		floodlightProviderService.addOFMessageListener(OFType.FLOW_MOD, this);
		floodlightProviderService.addOFMessageListener(OFType.PACKET_OUT, this);
		ScheduledExecutorService ses = threadPoolService.getScheduledExecutor();
		updateTask = new SingletonTask(ses, new Runnable() {
			int counter = 0;
			@Override
			public void run() {
				// TODO Auto-generated method stub
				while(!updateQueue.isEmpty()){
					OFMessage msg = updateQueue.remove();
					OFType key = msg.getType();
					
					if(RECORD_TYPE_SET.containsKey(key)){
						collector.get(key).plusOne();;
					}
				}
				
				if(counter == 0) {
					printId ++;
					for(OFType i:collector.keySet()){
						ReferenceInterger interger = collector.get(i);
						print(printId,  i, interger);
						interger.clear();
					}
				}
				counter = (counter + 1) % PRINT_INTERVAL;
				
				updateTask.reschedule(UPDATE_TASK_INTERVAL, TimeUnit.MILLISECONDS);
			}
		});
		updateTask.reschedule(UPDATE_TASK_INTERVAL, TimeUnit.MILLISECONDS);
	}

	@Override
	public String getName() {
		// TODO Auto-generated method stub
		return "savi-statistics";
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg,
			FloodlightContext cntx) {
		// TODO Auto-generated method stub
	
		if(this.enableAutocalculate && filter(sw,msg)) {
			updateQueue.add(msg);
		}
		
		return Command.CONTINUE;
	}

	@Override
	public void disableAutoCalculation(boolean enable) {
		// TODO Auto-generated method stub
		this.enableAutocalculate = enable;
	}

	@Override
	public void updateMessage(OFMessage msg) {
		// TODO Auto-generated method stub
		updateQueue.add(msg);
	}
}
