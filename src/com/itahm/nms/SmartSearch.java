package com.itahm.nms;

import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Iterator;

import org.snmp4j.CommunityTarget;
import org.snmp4j.PDU;
import org.snmp4j.ScopedPDU;
import org.snmp4j.Snmp;
import org.snmp4j.Target;
import org.snmp4j.UserTarget;
import org.snmp4j.event.ResponseEvent;
import org.snmp4j.event.ResponseListener;
import org.snmp4j.mp.SnmpConstants;
import org.snmp4j.smi.Address;
import org.snmp4j.smi.Integer32;
import org.snmp4j.smi.OID;
import org.snmp4j.smi.OctetString;
import org.snmp4j.smi.UdpAddress;
import org.snmp4j.smi.VariableBinding;

import com.itahm.nms.Bean.Profile;
import com.itahm.util.Listener;
import com.itahm.util.Network;

public class SmartSearch implements Runnable, ResponseListener {

	private final static long TIMEOUT = 5000L;
	
	private final Thread thread = new Thread(this, "Smart Search");
	private final Snmp snmpServer;
	private final Network network;
	private final Profile [] profile;
	private final ArrayList<Listener> listenerList = new ArrayList<Listener>();
	
	public SmartSearch(Snmp snmp, Network network, Profile ...profile) {
		snmpServer = snmp;
		this.network = network;
		this.profile = profile;
		
		thread.setName(String.format("%s %s","SmartSearch", network));
		thread.setDaemon(true);
	}
	
	public void start() {
		this.thread.start();
	}
	
	public void addEventListener(Listener listener) {
		this.listenerList.add(listener);	
	}

	public void removeEventListener(Listener listener) {
		this.listenerList.remove(listener);	
	}
	
	@Override
	public void run() {	
		Target<UdpAddress> target;
		PDU request;
		String ip, name;
		UdpAddress udp;
		int version;
		
		
		for (Profile profile: this.profile) {
			name = profile.name;
			
			switch(profile.version) {
			case 3:
				target = new UserTarget<>();
				
				target.setSecurityName(new OctetString(profile.security));
				target.setSecurityLevel(profile.level);
				
				request = new ScopedPDU();
				
				version = SnmpConstants.version3;
				
				break;
			case 1:
				target = new CommunityTarget<>();
					
				((CommunityTarget<UdpAddress>)target).setCommunity(new OctetString(profile.security));
				
				request = new PDU();
				
				version = SnmpConstants.version2c;
				
				break;
				
			default:
				target = new CommunityTarget<>();
				
				((CommunityTarget<UdpAddress>)target).setCommunity(new OctetString(profile.security));
				
				request = new PDU();
				
				version = SnmpConstants.version1;	
			}
			
			target.setVersion(version);
			
			target.setTimeout(TIMEOUT);
			target.setRetries(0);
			
			request.setType(PDU.GETNEXT);
			request.add(new VariableBinding(new OID(new int [] {1,3,6,1,2,1})));
			
			udp = new UdpAddress(profile.port);
			
			for (Iterator<String> it = network.iterator(); it.hasNext(); ) {
				ip = it.next();
				
				try {
					udp.setInetAddress(InetAddress.getByName(ip));
					
					target.setAddress(udp);
					
					request.setRequestID(new Integer32(0));
					
					this.snmpServer.send(request, target, new Args(ip, name), this);
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	@Override
	public <A extends Address> void onResponse(ResponseEvent<A> event) {
		try {
			if (event == null) {
				throw new IOException("null event.");
			}
			else {				
				Object source = event.getSource();
				PDU response = event.getResponse();
				Args args = (Args)event.getUserObject();
				Address address = event.getPeerAddress();
				
				if (!(source instanceof Snmp.ReportHandler) &&
					address instanceof UdpAddress &&
					((UdpAddress)address).getInetAddress().getHostAddress().equals(args.ip) &&
					response != null &&
					response.getErrorStatus() == SnmpConstants.SNMP_ERROR_SUCCESS) {
					((Snmp)source).cancel(event.getRequest(), this);
					//Net Search??? ?????? ???????????? base??? ????????? ??? ?????? ????????? Node??? ?????? ??? ?????? ??????.

					for (Listener listener: this.listenerList) {
						listener.onEvent(this, args.ip, args.profile);
					}
				}
			}
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}		
	}
	
	private class Args {
		private final String profile;
		private final String ip;
		
		private Args(String ip, String profile) {
			this.ip = ip;
			this.profile = profile;
		}
	}

}
