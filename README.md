COMP4203-IDS
============
When running the IDS, it will display all device interfaces and prompt you to select a device.
Select the network device you will be using to monitor incoming packets.
Incoming packet information will be displayed.

To manually test by sending packets yourself follow these steps:

  1. Make sure port 7000 is open on your gateway.
  2. Run the IDS.
  3. Open two terminals, t1 and t2.
  4. On t1 run "nc -lu 7000" to create a server that listens for udp packets.
  5. On t2 run "nc -4u <Host's IP> 7000" to open a connection.
  6. Type input to be sent in t2.
  7. Examine packet data in the IDS
