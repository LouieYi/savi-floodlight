package net.floodlightcontroller.savi.statistics;

import org.projectfloodlight.openflow.protocol.OFMessage;

import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

public interface ISAVIStatistics extends IFloodlightService{
	public void write(IOFSwitch sw, OFMessage msg);
	public void updateMessage(OFMessage msg);
	public void disableAutoCalculation(boolean enable);
}
