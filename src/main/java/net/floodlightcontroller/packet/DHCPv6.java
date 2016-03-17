package net.floodlightcontroller.packet;

import java.nio.ByteBuffer;
import java.util.List;

import org.projectfloodlight.openflow.types.IPv6Address;
import org.projectfloodlight.openflow.types.MacAddress;

public class DHCPv6 extends BasePacket {
	
	protected byte msgType;
	protected int transactionId;
	protected List<DHCPv6Option> options;
	protected short duidType;
	protected short hardwareType;
	protected int time;
	protected MacAddress linkLayerAddress;
	protected int iaid;
	protected int t1;
	protected int t2;
	protected int validLifetime;
	protected int preferredLifetime;
	protected IPv6Address targetAddress;
	
	public static final byte SOLICIT 				= 1 ;
	public static final byte ADVERTISE 				= 2 ;
	public static final byte REQUEST 				= 3 ;
	public static final byte CONFIRM 				= 4 ;
	public static final byte RENEW 					= 5 ;
	public static final byte REBIND					= 6 ;
	public static final byte REPLY					= 7 ;
	public static final byte RELEASE				= 8 ;
	public static final byte DECLINE				= 9 ;
	public static final byte RECONFIGURE 			= 10;
	public static final byte INFORMATION_REQUEST	= 11;
	public static final byte RELAY_FORW				= 12;
	public static final byte RELAY_REPL				= 13;
	
	public int getTime() {
		return time;
	}
	public int getValidLifetime() {
		return validLifetime;
	}
	public int getIaid() {
		return iaid;
	}
	public void setIaid(int iaid) {
		this.iaid = iaid;
	}
	public int getT1() {
		return t1;
	}
	public void setT1(int t1) {
		this.t1 = t1;
	}
	public int getT2() {
		return t2;
	}
	public void setT2(int t2) {
		this.t2 = t2;
	}
	public IPv6Address getTargetAddress() {
		return targetAddress;
	}
	public short getDuidType() {
		return duidType;
	}
	public short getHardwareType() {
		return hardwareType;
	}
	public MacAddress getLinkLayerAddress() {
		return linkLayerAddress;
	}
	public byte getMsgType(){
		return msgType;
	}
	
	public int getTransactionId() {
		return transactionId;
	}
	public void setTransactionId(int transactionId) {
		this.transactionId = transactionId;
	}
	@Override
	public byte[] serialize() {
		// TODO Auto-generated method stub
		int length = 4;
		for(DHCPv6Option option:options){
			length += option.getLength() + 4;
		}
		byte[] data = new byte[length];
		data[0] = msgType;
		data[1] = (byte)(transactionId>>16);
		data[2] = (byte)(transactionId>>8);
		data[3] = (byte)(transactionId);
		ByteBuffer bb = ByteBuffer.wrap(data,4,data.length);
		for(DHCPv6Option option:options){
			bb.put(option.serilize());
		}
		return data;
	}

	@Override
	public IPacket deserialize(byte[] data, int offset, int length) throws PacketParsingException {
		// TODO Auto-generated method stub
		time = 0;
		validLifetime = 0;
		
		msgType = data[offset];
		transactionId += data[offset + 1];
		transactionId = (transactionId<<8) + data[offset + 2];
		transactionId = (transactionId<<8) + data[offset + 3];
		options = DHCPv6Option.getOptions(data, offset + 4);
		
		for(DHCPv6Option option:options){
			ByteBuffer bb = null;
			switch(option.getCode()){
			case DHCPv6Option.CLIENT_IDENTIFIER:
				bb = ByteBuffer.wrap(option.getData());
				duidType = bb.getShort();
				hardwareType = bb.getShort();
				time = bb.getInt();
				byte[] tmp = new byte[6];
				bb.get(tmp);
				linkLayerAddress = MacAddress.of(tmp);
				break;
			case DHCPv6Option.IDENTITY_ASSOCIATION:
				bb = ByteBuffer.wrap(option.getData());
				iaid = bb.getInt();
				t1 = bb.getInt();
				t2 = bb.getInt();
				if(option.length>12&&bb.getShort() == 5){
					bb.getShort();
					byte[] addr = new byte[16];
					bb.get(addr);
					targetAddress = IPv6Address.of(addr);
					preferredLifetime = bb.getInt();
					validLifetime = bb.getInt();
				}
				break;
			default:
				break;
			}
		}
		return this;
	}

}
