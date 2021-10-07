
#Mariam Safieldin and Peter Farah develloped this Detection code

from scapy.all import *
from collections import Counter
from time import localtime, strftime
import logging
import time



#log attacks at what time
class LOG():#logging attack by Mariam
    
     @staticmethod
     def run(ip):

        date = strftime("%a, %d %b %Y %X", localtime())
        logging.info("Status at "+ str(date) + ": a TCP SYN Flood Attack is Detected! with latest IP:"+ip)



def analyzer(pkt):#detection logic by Peter
                  #packet sniffing and passing throw function by Mariam
    
    global a#number of packets that are tcp syn
    global start#used for timing
    global th#Threshold number for attack detection
    
    #checking if packet is a TCP SYN packet by Mariam
    if TCP in pkt and pkt[TCP].flags & 2:
        src = pkt.sprintf('{IP:%IP.src%}{IPv6:%IPv6.src%}')
        a=a+1#increment a evry time we have a tcp syn
    
    #evry 5s reset number of tcp syn packets loged to 0 by Peter
    if ((time.time()-start)>=5):
        a=0
        start=time.time()
    #when a=100 log that an attacked is regestered and set a to 80 by Peter
    elif (a>=th):#deppends on the server change the number
        a=int(0.8*th)
        LOG.run(src)
        



    
#Saving an analysis of the traffic  by Mariam
logging.basicConfig(filename='packets_breakdown.log', format='%(message)s', level=logging.INFO)

#initialising some variables by Peter
global a#number of packets that are tcp syn
global start#for timing
global th
th=abs(int( input("Input Threshold number for attack detection/5s: ")))
start=time.time()
a=0

#sniffing packets and passing them through the analyzer by Mariam
sniff(prn=analyzer, store=0)