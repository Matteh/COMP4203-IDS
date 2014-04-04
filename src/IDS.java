import java.awt.EventQueue;
import java.awt.Graphics;
import java.awt.Rectangle;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.SocketException;

import javax.swing.ButtonGroup;
import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.border.EmptyBorder;
import javax.swing.text.DefaultCaret;

import java.util.ArrayList;
import java.util.Enumeration;
import java.util.HashMap;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.List;

import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import org.jnetpcap.packet.JPacket;
import org.jnetpcap.packet.JPacketHandler;
import org.jnetpcap.packet.format.FormatUtils;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.tcpip.Udp;

import javax.swing.JComboBox;
import javax.swing.JLabel;

public class IDS extends JFrame implements ActionListener {

	/**
*
*/
	private static final long serialVersionUID = 1L;
	private JPanel contentPane;
	private JButton scanButton;
	private JTextArea textArea;
	private JComboBox comboBox;
	private JRadioButton radio1, radio2;
	private ButtonGroup group;

	// Stores all interface devices
	List<PcapIf> alldevs = new ArrayList<PcapIf>();

	// Address on the LAN, default set to localhost.
	String localAddr = "127.0.0.1";
	StringBuilder errbuf = new StringBuilder();

	int devChoice;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					IDS frame = new IDS();
					frame.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the frame.
	 * 
	 * @throws SocketException
	 */
	public IDS() throws SocketException {

		// Initialize the GUI

		setTitle("UDP Flooding IDS");
		setIconImage(Toolkit.getDefaultToolkit().getImage(
				IDS.class.getResource("/img/lock.png")));
		setResizable(false);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setBounds(100, 100, 900, 550);
		contentPane = new JPanel();
		contentPane.setBounds(new Rectangle(100, 100, 780, 500));
		contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
		setContentPane(contentPane);
		contentPane.setLayout(null);

		textArea = new JTextArea();
		textArea.setEditable(false);
		textArea.setBounds(32, 39, 500, 450);
		contentPane.add(textArea);

		scanButton = new JButton("Scan");
		scanButton.setBounds(761, 464, 117, 25);
		scanButton.addActionListener(this);
		contentPane.add(scanButton);

		comboBox = new JComboBox();
		comboBox.setBounds(664, 88, 198, 25);
		contentPane.add(comboBox);
		
		group = new ButtonGroup();
		radio1 = new JRadioButton("Algorithm 1");
		radio1.setBounds(664, 150, 198, 25);
		radio2 = new JRadioButton("Algorithm 2");
		radio2.setBounds(664, 175, 198, 25);
		group.add(radio1);
		group.add(radio2);
		contentPane.add(radio1);
		contentPane.add(radio2);
		radio1.setSelected(true);

		DefaultCaret caret = (DefaultCaret) textArea.getCaret();
		caret.setUpdatePolicy(DefaultCaret.ALWAYS_UPDATE);
		textArea.setWrapStyleWord(true);
		textArea.setCaretPosition(textArea.getDocument().getLength());

		JScrollPane scroll = new JScrollPane(textArea,
				JScrollPane.VERTICAL_SCROLLBAR_ALWAYS,
				JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
		scroll.setSize(615, 450);
		scroll.setLocation(20, 27);
		contentPane.add(scroll);

		JLabel lblNetworkInterfaces = new JLabel("Network Interfaces:");
		lblNetworkInterfaces.setBounds(664, 61, 192, 15);
		contentPane.add(lblNetworkInterfaces);

		// Add interface devices to the list of devices
		int r = Pcap.findAllDevs(alldevs, errbuf);
		if (r == Pcap.NOT_OK || alldevs.isEmpty()) {
			textArea.append(String.valueOf(alldevs.size()));
			textArea.append("\nCan't read list of devices, error is "
					+ errbuf.toString());
			return;
		}

		// Printing the list of devices and awaiting user input for a selected
		// device
		textArea.append("Network devices found:\n\n");
		int i = 0;
		for (PcapIf device : alldevs) {
			String description = (device.getDescription() != null) ? device
					.getDescription() : "No description available";
			textArea.append("#" + i++ + ": " + device.getName() + " ["
					+ description + "]\n");
			comboBox.addItem(device.getName());
		}

	}

	public void runIDS(int d) throws IOException {

		final PcapIf device = alldevs.get(d);
		// TODO Doesn't dynamically update the JTextArea
		textArea.append("\nChoosing '"
				+ ((device.getDescription() != null) ? device.getDescription()
						: device.getName()) + "':\n");

		// Finds the LAN IP address of the host from network interfaces
		Enumeration<NetworkInterface> n = NetworkInterface
				.getNetworkInterfaces();
		while (n.hasMoreElements()) {
			NetworkInterface e = n.nextElement();

			Enumeration<InetAddress> a = e.getInetAddresses();

			while (a.hasMoreElements()) {
				InetAddress addr = a.nextElement();
				if ((addr instanceof Inet4Address)
						&& (!(addr.getHostAddress().equals("127.0.0.1")))) {
					localAddr = addr.getHostAddress();
					// TODO Doesn't dynamically update the JTextArea
					textArea.append("\nHost address: " + localAddr + "\n");
				}

			}

		}

		// Stores the LAN IP address of the host.
		final String hostAddr = localAddr;

		// Retrieve default gateway address
		String[] cmd = { "/bin/sh", "-c",
				"netstat -rn | grep 0.0.0.0 | awk \'{print $2}\' | grep -v \"0.0.0.0\"" };
		Process result = Runtime.getRuntime().exec(cmd);
		BufferedReader output = new BufferedReader(new InputStreamReader(
				result.getInputStream()));
		final String defaultGate = output.readLine();
		textArea.append("Default Gateway: " + defaultGate + "\n");

		// Packet capturing settings
		int snaplen = 64 * 1024;
		int flags = Pcap.MODE_PROMISCUOUS;
		int timeout = 10 * 1000;
		// Open capturing channel
		final Pcap pcap = Pcap.openLive(device.getName(), snaplen, flags,
				timeout, errbuf);

		if (pcap == null) {
			textArea.append("Error while opening device for capture: "
					+ errbuf.toString());
			return;
		}

		// Main handler when a packet is captured
		JPacketHandler<String> jpacketHandler1 = new JPacketHandler<String>() {
			Udp udp = new Udp();
			Ip4 ip = new Ip4();
			// Tcp tcp = new Tcp();
			int counter = 0;

			boolean exitFlag = false;

			// Stores source IPs and their corresponding data sent to the host
			// (in bytes)
			HashMap<String, Integer> sources = new HashMap<String, Integer>();
			HashMap<String, Long> startTimes = new HashMap<String, Long>();

			long bpsLimit = 60000;

			public void nextPacket(JPacket packet, String user) {

				// Holds the source and destination IP addresses
				byte[] sIP = new byte[4];
				byte[] dIP = new byte[4];
				double bps = 0;

				if (!(packet.hasHeader(ip))) {
					return;
				}
				// Sets the source and destination IP addresses to those in the
				// captured packet header.
				dIP = packet.getHeader(ip).destination();
				sIP = packet.getHeader(ip).source();
				ip.sourceToByteArray(sIP);
				ip.destinationToByteArray(dIP);

				// Formatting the IP addresses to standard convention
				String sourceIP = FormatUtils.ip(sIP);
				String destinationIP = FormatUtils.ip(dIP);

				// Displays the packet information such as source and
				// destination IP addresses along with ports and the size of
				// each packet in bytes.
				if ((packet.hasHeader(udp)) && (packet.hasHeader(ip))) {

					// Filters out packets sent by the current host.
					if (destinationIP.equals(hostAddr)) {

						// Add source IP to the map
						if (!(sources.containsKey(sourceIP))) {
							sources.put(sourceIP, 0);
							startTimes
									.put(sourceIP, System.currentTimeMillis());
						}

						// Refresh start times
						if (((System.currentTimeMillis() - startTimes
								.get(sourceIP)) / 60000) > 1) {
							startTimes
									.put(sourceIP, System.currentTimeMillis());
							sources.put(sourceIP, 0);
						}

						// Update the total received data for the corresponding
						// source IP
						sources.put(sourceIP,
								sources.get(sourceIP) + packet.size());
						// TODO Doesn't dynamically update the JTextArea
						textArea.append("Incoming UDP packet, source: "
								+ sourceIP + ":" + udp.source() + " "
								+ "destination: " + destinationIP + ":"
								+ udp.destination() + " size " + packet.size()
								+ "\n");
						if (((System.currentTimeMillis() - startTimes
								.get(sourceIP)) / 1000) >= 10) {
							bps = (double) (sources.get(sourceIP) / (double) ((System
									.currentTimeMillis() - startTimes
									.get(sourceIP)) / 1000));
						}

						if (bps > bpsLimit) {
							JOptionPane.showMessageDialog(null,
									"UDP Flood from: " + sourceIP);
							exitFlag = true;
						}

						// For every 50 packets received print the hashmap of
						// all source IPs and their corresponding data (in
						// bytes)
						if (counter++ == 50) {
							textArea.append(sources.toString());
							counter = 0;
							textArea.update(textArea.getGraphics());
						}

						if (exitFlag) {
							pcap.breakloop();
						}
					}
				}
			}
		};
		
		JPacketHandler<String> jpacketHandler2 = new JPacketHandler<String>() {
			

			public void nextPacket(JPacket packet, String user) {

			}
		};

		// Packet capturing loop that currently does not end until termination
		// by user.
		if (radio1.isSelected())
			pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler1, "Capturing!");
		else if (radio2.isSelected())
			pcap.loop(Pcap.LOOP_INFINITE, jpacketHandler2, "Capturing!");
		textArea.update(textArea.getGraphics());
		pcap.close();

	}

	class ValidateThread implements Runnable {

		@Override
		public void run() {
			// TODO Auto-generated method stub

			// Get the users choice from the drop down list of network
			// interfaces
			int choice = comboBox.getSelectedIndex();

			try {
				runIDS(choice);
			} catch (SocketException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

		}

	}

	@Override
	public void actionPerformed(ActionEvent arg0) {

		if (arg0.getSource() == scanButton) {
			Runnable runnable = new ValidateThread();
			Thread thread = new Thread(runnable);
			thread.start();
		}

	}
}