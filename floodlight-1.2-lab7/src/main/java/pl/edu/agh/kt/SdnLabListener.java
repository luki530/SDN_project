package pl.edu.agh.kt;

import java.util.*;

import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.TCP;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFPacketIn;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.OFPort;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;


import net.floodlightcontroller.packet.IPv4;

import net.floodlightcontroller.core.IFloodlightProviderService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SdnLabListener implements IFloodlightModule, IOFMessageListener {

	protected IFloodlightProviderService floodlightProvider;
	protected static Logger logger;

	Map<String, Integer> impostorScore = new HashMap<String, Integer>();
	Map<String, List> impostorLast10Ports = new HashMap<String, List>();
	Map<String, List> impostorLast10DestIps = new HashMap<String, List>();


	@Override
	public String getName() {
		return SdnLabListener.class.getSimpleName();
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

		logger.info("************* NEW PACKET IN *************");
		PacketExtractor extractor = new PacketExtractor();
		extractor.packetExtract(cntx);

		Ethernet eth = extractor.getEth();
		if (eth.getEtherType() == EthType.IPv4) {
			IPv4 ipv4 = (IPv4) eth.getPayload();
			if (ipv4.getProtocol() == IpProtocol.TCF) {
				TCP tcp = (TCP) ipv4.getPayload();
				String src_ip = ipv4.getSourceAddress().toString();
				String dst_ip = ipv4.getDestinationAddress().toString();
				int dst_port = tcp.getDestinationPort().getPort();
				if (impostorScore.containsKey(src_ip)) {
					impostorLast10DestIps.get(src_ip).add(dst_ip);
					impostorLast10Ports.get(src_ip).add(dst_port);
					if (maliciousPort(dst_port)){
						impostorScore.put(src_ip, impostorScore.get(src_ip)+1);
					}
					if (impostorLast10Ports.get(src_ip).size() == 10){
						List<Integer> newPortsList = impostorLast10Ports.get(src_ip).subList(1, 10);
						newPortsList.add(dst_port);
						impostorLast10Ports.put(src_ip,newPortsList);
						List<String> newIPsList = impostorLast10DestIps.get(src_ip).subList(1, 10);
						newIPsList.add(dst_ip);
						impostorLast10Ports.put(src_ip,newIPsList);
					}
				} else {
					impostorScore.put(src_ip, 0);
					List<String> lastIps = new ArrayList<>();
					lastIps.add(dst_ip);
					impostorLast10DestIps.put(src_ip, lastIps);
					List<Integer> lastPorts = new ArrayList<>();
					lastPorts.add(dst_port);
					impostorLast10Ports.put(src_ip, lastPorts);
				}
			}
		}
		// TODO LAB 6
		OFPacketIn pin = (OFPacketIn) msg;
		OFPort outPort = OFPort.of(0);
		if (pin.getInPort() == OFPort.of(1)) {
			outPort = OFPort.of(2);
		} else
			outPort = OFPort.of(1);
		Flows.simpleAdd(sw, pin, cntx, outPort);

		return Command.STOP;
	}

	private boolean maliciousPort(int dst_port) {
		return true;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		logger = LoggerFactory.getLogger(SdnLabListener.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
		logger.info("******************* START **************************");

	}

}
