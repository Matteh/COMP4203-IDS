
import java.util.ArrayList;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

public class IDS {

	@SuppressWarnings("deprecation")
	public static void main(String[] args) {
		List<PcapIf> alldevs = new ArrayList<PcapIf>(); 
		StringBuilder errbuf = new StringBuilder(); 


		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			System.out.println(alldevs.size());
			System.err.printf("Can't read list of devices, error is %s", errbuf.toString());
			return;
		}

		System.out.println("Network devices found:");

		int i = 0;
		int deviceIndex = 0;
		for (PcapIf device : alldevs) {
			String description =
			    (device.getDescription() != null) ? device.getDescription()
			        : "No description available";
			System.out.printf("#%d: %s [%s]\n", i++, device.getName(), description);
			if (device.getName().equals("wlan0"))
				deviceIndex = (i - 1);
		}
		
		PcapIf device = alldevs.get(deviceIndex);
		System.out.printf("\nChoosing '%s':\n",(device.getDescription() != null) ? device.getDescription() : device.getName());

		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 10 * 1000;           
		Pcap pcap =
		    Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

		if (pcap == null) {
			System.err.printf("Error while opening device for capture: "
			    + errbuf.toString());
			return;
		}

		JPacketHandler<String> jpacketHandler = new JPacketHandler<String>() {  
		    Udp udp = new Udp();
		    //Ip4 ip = new Ip4();
		    Ethernet eth = new Ethernet();
		    
		    int total = 0;
		    public void nextPacket(JPacket packet, String user) {  
		    
				byte[] sIP = new byte[4];
				byte[] dIP = new byte[4];  
				
				if (!(packet.hasHeader(eth))){
					System.out.println("ERROR: NO ETHERNET HEADER");
					return;
				}
				eth.sourceToByteArray(sIP);
				eth.destinationToByteArray(dIP);
				
				String sourceIP = FormatUtils.ip(sIP);  
				String destinationIP = FormatUtils.ip(dIP);
				
		    	if((packet.hasHeader(udp)) && (packet.hasHeader(eth))) {  
		    		total += packet.size();
		            System.out.printf("Found UDP packet, source %s:%d destination %s:%d size %d\n", sourceIP, udp.source(), destinationIP, udp.destination(), packet.size());
		            System.out.printf("Total size = %d bytes\n", total);
		        }  
		    }
 
		};
		pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler, "jNetPcap rocks!");
		pcap.close();
	}
}