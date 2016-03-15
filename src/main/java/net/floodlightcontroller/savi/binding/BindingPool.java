package net.floodlightcontroller.savi.binding;

import java.util.HashMap;
import java.util.Map;

import org.projectfloodlight.openflow.types.MacAddress;
import org.python.antlr.PythonParser.raise_stmt_return;

import net.floodlightcontroller.devicemanager.SwitchPort;

public class BindingPool<T>{
	protected Map<T, Binding<T>> bindingTable;
	protected Map<MacAddress, SwitchPort> hardwareBindingTable;
	
	public BindingPool() {
		// TODO Auto-generated constructor stub
		bindingTable = new HashMap<>();
		hardwareBindingTable = new HashMap<>();
	}
	
	public boolean isBindingLeaseExpired(T address){
		Binding<T> binding = bindingTable.get(address);
		if(binding == null){
			return false;
		}
		else{
			return binding.isLeaseExpired();
		}
	}
	
	public void renewBiningLease(T address, int leaseTime){
		Binding<T> binding = bindingTable.get(address);
		if(binding != null){
			binding.setBindingTime();
			binding.setLeaseTime(leaseTime);
		}
	}
	
	public void addHardwareBinding(MacAddress macAddress,SwitchPort switchPort){
		hardwareBindingTable.put(macAddress, switchPort);
	}
	
	public void delHardwareBinding(MacAddress macAddress){
		hardwareBindingTable.remove(macAddress);
	}
	
	public boolean isContain(MacAddress macAddress){
		return hardwareBindingTable.containsKey(macAddress);
	}
	
	public boolean isContain(T address){
		return bindingTable.containsKey(address);
	}
	
	public SwitchPort getSwitchPort(MacAddress macAddress){
		return hardwareBindingTable.get(macAddress);
	}
	
	public Binding<T> getBinding(T address){
		return bindingTable.get(address);
	}
	
	public void addBinding(T address, Binding<T> binding){
		bindingTable.put(address, binding);
	}
	
	public void delBinding(T address){
		bindingTable.remove(address);
	}
	
	public boolean check(MacAddress macAddress, SwitchPort switchPort){
		if(hardwareBindingTable.containsKey(macAddress)){
			SwitchPort tmp = hardwareBindingTable.get(macAddress);
			if(tmp.equals(switchPort)){
				return true;
			}
		}
		return false;
	}
	
	public boolean check(T address, MacAddress macAddress){
		if(bindingTable.containsKey(address)){
			Binding<T> tmp = bindingTable.get(address);
			if(macAddress.equals(tmp.getMacAddress())){
				return true;
			}
		}
		return false;
	}
	
	public boolean check(T address, MacAddress macAddress, SwitchPort switchPort){
		return check(macAddress, switchPort)&&check(address, macAddress);
	}
}

