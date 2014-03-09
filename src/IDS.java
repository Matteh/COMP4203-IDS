
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.List;
import java.util.Scanner;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;

public class IDS {

	@SuppressWarnings("deprecation")
	public static void main(String[] args) throws IOException {
		//Stores all interface devices
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); 
		
		//Address on the LAN, default set to localhost.
		String localAddr = "127.0.0.1";
		StringBuilder errbuf = new StringBuilder(); 

		//Add interface devices to the list of devices
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.out.println(alldevs.size());
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}
		
		//Printing the list of devices and awaiting user input for a selected device
		System.out.println("Network devices found:");
		int i = 0;
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
		}
		int devChoice = -1;
		Scanner input = new Scanner(System.in);
		while ((devChoice < 0) || (devChoice >= i)){
			System.out.println("Enter the index of a device");
			devChoice = input.nextInt();
			if ((devChoice < 0) || (devChoice >= i)){
				System.out.println("Error: Input device does not exist");
			}
		}	
		final PcapIf device = alldevs.get(devChoice);
		System.out.printf("\nChoosing '%s':\n",(device.getDescription() != null) ? device.getDescription() : device.getName());
		
		//Finds the LAN IP address of the host from network interfaces
		Enumeration<NetworkInterface> n = NetworkInterface.getNetworkInterfaces();
		while (n.hasMoreElements()) {
			NetworkInterface e = n.nextElement();

			Enumeration<InetAddress> a = e.getInetAddresses();
			
			while(a.hasMoreElements()) {
				InetAddress addr = a.nextElement();
				if ((addr instanceof Inet4Address) && (!(addr.getHostAddress().equals("127.0.0.1")))){
					localAddr = addr.getHostAddress();
					System.out.printf("\nHost address: %s\n", localAddr);
				}

			}
		}
		
		//Stores the LAN IP address of the host.
		final String hostAddr = localAddr;

		//Retrieve default gateway address
		String[] cmd = {"/bin/sh","-c","netstat -rn | grep 0.0.0.0 | awk \'{print $2}\' | grep -v \"0.0.0.0\""};
		Process result = Runtime.getRuntime().exec(cmd);
	    BufferedReader output = new BufferedReader(new InputStreamReader(result.getInputStream()));
	    final String defaultGate = output.readLine();
	    System.out.printf("Default Gateway: %s\n\n", defaultGate);

	    
		//Packet capturing settings
		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 10 * 1000;  
		//Open capturing channel
		Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}
		
		//Main handler when a packet is captured
		JPacketHandler<String> jpacketHandler = new JPacketHandler<String>() {  
		    Udp udp = new Udp();
		    Ip4 ip = new Ip4();
		    //Tcp tcp = new Tcp();
		    int counter = 0;
		    
		    //Stores source IPs and their corresponding data sent to the host (in bytes)
		    HashMap<String, Integer> sources = new HashMap<String, Integer>();
		    
		    public void nextPacket(JPacket packet, String user) {  
		    	
		    	//The source and destination IP addresses
				byte[] sIP = new byte[4];
				byte[] dIP = new byte[4];  
				
				
				if (!(packet.hasHeader(ip))){
					return;
				}
				//Sets the source and destination IP addresses to those in the captured packet header.
				dIP = packet.getHeader(ip).destination();
				sIP = packet.getHeader(ip).source();
				ip.sourceToByteArray(sIP);
				ip.destinationToByteArray(dIP);
				
				
				//Formatting the IP addresses to standard convention
				String sourceIP = FormatUtils.ip(sIP);  
				String destinationIP = FormatUtils.ip(dIP);

				//Displays the packet information such as source and destination IP addresses along with ports and the size of each packet in bytes.
		    	if((packet.hasHeader(udp)) && (packet.hasHeader(ip))) {  
		    		
		    		//Filters out unwanted packet information.
		    		if (!(sourceIP.equals(hostAddr)) && (!(sourceIP.equals(defaultGate))) && (destinationIP.equals(hostAddr))){
		    			
		    			//Add source IP to the map
		    			if (!(sources.containsKey(sourceIP))){
		    				sources.put(sourceIP, 0);
		    			}
		    			
		    			//Update the total received data for the corresponding source IP
		    			sources.put(sourceIP, sources.get(sourceIP) + packet.size());
		    			System.out.printf("Found UDP packet, source %s:%d destination %s:%d size %d\n", sourceIP, udp.source(), destinationIP, udp.destination(), packet.size());
		    			
		    			//For every 50 packets received print the hashmap of all source IPs and their corresponding data (in bytes)
		    			if (counter++ == 50){
		    				System.out.println(sources.toString());
		    				counter = 0;
		    			}
		    		}
		        }  
		    }
 
		};
		
		//Packet capturing loop that currently does not end until termination by user.
		pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "Capturing!");
		pcap.close();
	}
}