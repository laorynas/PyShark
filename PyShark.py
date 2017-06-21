#Requires: whois && socket
import socket, sys, os, time
from struct import *

print """                                                                                                                                     
 /$$$$$$$             /$$$$$$  /$$                           /$$      
| $$__  $$           /$$__  $$| $$                          | $$      
| $$  \ $$ /$$   /$$| $$  \__/| $$$$$$$   /$$$$$$   /$$$$$$ | $$   /$$
| $$$$$$$/| $$  | $$|  $$$$$$ | $$__  $$ |____  $$ /$$__  $$| $$  /$$/
| $$____/ | $$  | $$ \____  $$| $$  \ $$  /$$$$$$$| $$  \__/| $$$$$$/ 
| $$      | $$  | $$ /$$  \ $$| $$  | $$ /$$__  $$| $$      | $$_  $$ 
| $$      |  $$$$$$$|  $$$$$$/| $$  | $$|  $$$$$$$| $$      | $$ \  $$
|__/       \____  $$ \______/ |__/  |__/ \_______/|__/      |__/  \__/
           /$$  | $$                                                  
          |  $$$$$$/                                                  
           \______/     Python Packet Sniffing with whois                                                                                                           
"""

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
except socket.error , msg:
    print 'Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1]
    sys.exit()
 
while True:
    packet = s.recvfrom(65565)
    packet = packet[0]
    ip_header = packet[0:20]
    iph = unpack('!BBHHHBBH4s4s' , ip_header)
    version_ihl = iph[0]
    version = version_ihl >> 4
    ihl = version_ihl & 0xF
    iph_length = ihl * 4
    ttl = iph[5]
    protocol = iph[6]
    s_addr = socket.inet_ntoa(iph[8]);
    d_addr = socket.inet_ntoa(iph[9]);
    print "========================================================================"
    print 'Captured Address: ', str(s_addr) 
    print 'Destination Address:', str(d_addr)
    print 
    print "Whois:"
    os.system('whois ' + str(s_addr) + '| grep "Address"')
    os.system('whois ' + str(s_addr) + '| grep "City"')
    os.system('whois ' + str(s_addr) + '| grep "OrgName"')

    tcp_header = packet[iph_length:iph_length+20]
    tcph = unpack('!HHLLBBHHH' , tcp_header)
    source_port = tcph[0]
    dest_port = tcph[1]
    sequence = tcph[2]
    acknowledgement = tcph[3]
    doff_reserved = tcph[4]
    tcph_length = doff_reserved >> 4
    h_size = iph_length + tcph_length * 4
     
