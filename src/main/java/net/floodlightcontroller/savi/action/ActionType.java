package net.floodlightcontroller.savi.action;

public enum ActionType{
	DROP,
	PACKET_OUT,
	PACKET_OUT_MULTI_PORT,
	FLOOD,
	FLOW_MOD,
	BIND_IPv4,
	BIND_IPv6,
	UNBIND_IPv4,
	UNBIND_IPv6,
	CLEAR_IPv4_BINDING,
	CLEAR_IPv6_BINDING,
	CLEAR_SWITCH_BINDING,
	CLEAR_PORT_BINDING,
	CLEAR_MAC_BINDING,
	CHECK_IPv4_BINDING,
	CHECK_IPv6_BINDING
}