package net.floodlightcontroller.savi.forwarding.mpls;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Queue;

import org.projectfloodlight.openflow.types.DatapathId;

import net.floodlightcontroller.devicemanager.SwitchPort;

public class MPLSLabelManager {
	public static int MAX_LABEL_NUMBER = 65536;
	
	static Queue<Integer> labelQueue;			// Available labels 
	static Map<Integer, SwitchPort> switchPortMap;
	Map<SwitchPort, Integer> labelMap;  // Unavailable labels
	
	static {
		switchPortMap = new HashMap<>();
		labelQueue = new LinkedList<>();
		for(int i = 1000; i<MAX_LABEL_NUMBER; i++){
			labelQueue.add(i);
		}
	}
	/**
	 * Simple constructor 
	 */
	public MPLSLabelManager(){
		labelMap = new HashMap<>();
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
	
	public static SwitchPort getSwitchPort(int label){
		return switchPortMap.get(label);
	}
	
	public Integer getLabel(SwitchPort switchPort){
		return labelMap.get(switchPort);
	}
	public void addLabel(SwitchPort switchPort,int label){
		synchronized(switchPortMap){
			switchPortMap.put(label, switchPort);
		}
		labelMap.put(switchPort, new Integer(label));
	}
	public Integer delLabel(SwitchPort switchPort) {
		Integer label = labelMap.get(switchPort);
		synchronized(switchPortMap){
			switchPortMap.remove(label);

		}
		synchronized(labelQueue){
			if(label!=null){
				labelQueue.add(label);
			}
		}
		return labelMap.remove(switchPort);
	}
	public void delLabels(List<SwitchPort> list) {
		for(SwitchPort switchPort:list){
			delLabel(switchPort);
		}
	}
	public boolean isContain(SwitchPort switchPort){
		return labelMap.containsKey(switchPort);
	}
	public void delSwitch(DatapathId dpid){
		for(SwitchPort switchPort:labelMap.keySet()){
			if(dpid.equals(switchPort.getSwitchDPID())){
				delLabel(switchPort);
			}
		}
	}
}
