package net.floodlightcontroller.savi.forwarding.mpls;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.concurrent.CopyOnWriteArrayList;

import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstruction;
import org.projectfloodlight.openflow.protocol.instruction.OFInstructionApplyActions;
import org.projectfloodlight.openflow.protocol.ver13.OFInstructionsVer13;
import org.projectfloodlight.openflow.types.DatapathId;

import net.floodlightcontroller.devicemanager.SwitchPort;

public class MPLSLabelManager {
	public static int MAX_LABEL_NUMBER = 65536;
	
	static Queue<Integer> labelQueue;			// Available labels 
	static Set<Integer> labelSet;				// Label in use
	
	protected static int MAX_LABEL_THRESHOLD = 4096*2;
	protected static int MIN_LABEL_THRESHOLD = 500;
	
	Map<DatapathId,Map<List<OFInstruction>,Integer>> switchLabelMap;
	
	Map<SwitchPort, Integer> labelMap;  // Unavailable labels
	
	static {
		labelQueue = new ConcurrentLinkedQueue<>();
		for(int i = 1000; i<MAX_LABEL_NUMBER; i++){
			labelQueue.add(i);
		}
	}
	/**
	 * Simple constructor 
	 */
	public MPLSLabelManager(){
		switchLabelMap = new ConcurrentHashMap<>();
		labelMap = new ConcurrentHashMap<>();
	}
	
	/**
	 * 
	 * @return a new label
	 */
	public static Integer allocateNewLabel(){
		Integer i = null;
		synchronized(labelQueue){
			i = labelQueue.remove();
		}
		if( i == null){
			return 0;
		}
		
		return i.intValue();
	}
	
	
	public Integer getLabel(DatapathId switchId, List<OFAction> actions) {
		if(switchLabelMap.containsKey(switchId)){
			Map<List<OFInstruction>,Integer> labelMap = switchLabelMap.get(switchId);
			
			OFInstructionApplyActions.Builder builder = new OFInstructionsVer13().buildApplyActions();
			builder.setActions(actions);
			
			List<OFInstruction> instructions = new ArrayList<>();
			instructions.add(builder.build());
			
			return labelMap.get(instructions);
			
		}
		return null;
	}
	
	
	public void addLabel(DatapathId switchId, List<OFAction> actions, int label) {
		OFInstructionApplyActions.Builder builder = new OFInstructionsVer13().buildApplyActions();
		builder.setActions(actions);
		List<OFInstruction> instructions = new CopyOnWriteArrayList<>();
		instructions.add(builder.build());
		Map<List<OFInstruction>,Integer> labelMap = null;
		
		if(switchLabelMap.containsKey(switchId)) {
			labelMap = switchLabelMap.get(switchId);
			labelMap.put(instructions, label);
		}
		else {
			labelMap = new ConcurrentHashMap<>();
			labelMap.put(instructions, label);
			switchLabelMap.put(switchId, labelMap);
		}
		labelMap.put(instructions, label);
	}
	
	public void delSwitch(DatapathId switchId) {
		switchLabelMap.remove(switchId);
	}
	
	public void delLabel(int label) {
		for(Map<List<OFInstruction>,Integer> m: switchLabelMap.values()){
			for(List<OFInstruction> list:m.keySet()) {
				Integer i = m.get(list);
				if(i.intValue() == label) {
					m.remove(list);
					break;
				}
			}
		}
	}
	
	public boolean isContain(SwitchPort switchPort){
		return labelMap.containsKey(switchPort);
	}
	
}
