import re
from scapy.all import *
from SIDS.IPs import *
from SIDS.Utils import *
from SIDS.Rule import *
from urllib.parse import unquote

# color formatting
RED = '\033[91m'
ENDC = '\033[0m'
GREEN = '\033[32m'

# TCP flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# display IPv4 header
def displayIP(ip) :
    print ("[IP]")
    print ("\t Version: " + str(ip.version))
    print ("\t IHL: " + str(ip.ihl * 4) + " bytes")
    print ("\t ToS: " + str(ip.tos))
    print ("\t Total Length: " + str(ip.len))
    print ("\t Identification: " + str(ip.id))
    print ("\t Flags: " + str(ip.flags))
    print ("\t Fragment Offset: " + str(ip.frag))
    print ("\t TTL: " + str(ip.ttl))
    print ("\t Protocol: " + str(ip.proto))
    print ("\t Header Checksum: " + str(ip.chksum))
    print ("\t Source: " + str(ip.src))
    print ("\t Destination: " + str(ip.dst))
    if (ip.ihl > 5):
        print ("\t Options: " + str(ip.options))

# Display the IPv4 header with matched fields in red
def displayMatchedIP(ip, rule):
    print ("[IP]")
    print ("\t Version: " + str(ip.version))

    if (hasattr(rule, "len")):
        print (RED + "\t IHL: " + str(ip.ihl * 4) + " bytes" + ENDC)
    else:
        print ("\t IHL: " + str(ip.ihl * 4) + " bytes")
    if (hasattr(rule, "tos")):
        print (RED + "\t ToS: " + str(ip.tos) + ENDC)
    else:
        print ("\t ToS: " + str(ip.tos))

    print ("\t Total Length: " + str(ip.len))
    print ("\t Identification: " + str(ip.id))
    print ("\t Flags: " + str(ip.flags))

    if (hasattr(rule, "offset")):
        print (RED + "\t Fragment Offset: " + str(ip.frag) + ENDC)
    else:
        print ("\t Fragment Offset: " + str(ip.frag))

    print ("\t TTL: " + str(ip.ttl))
    print ("\t Protocol: " + str(ip.proto))
    print ("\t Header Checksum: " + str(ip.chksum))

    # If the IP was specified uniquely, prin in red
    if (rule.srcIp.ipn.num_addresses == 1):
        print (RED + "\t Source: " + str(ip.src) + ENDC)
    else:
        print ("\t Source: " + str(ip.src))

    if (rule.dstIp.ipn.num_addresses == 1):
        print (RED + "\t Destination: " + str(ip.dst) + ENDC)
    else:
        print ("\t Destination: " + str(ip.dst))

    if (ip.ihl > 5):
        print ("\t Options : " + str(ip.options))

# Display the IPv6 header
def displayIPv6(ip) :
    print ("[IPv6]")
    print ("\t Version: " + str(ip.version))
    print ("\t Header Length: " + str(40) + " bytes")
    print ("\t Flow Label: " + str(ip.fl))
    print ("\t Traffic Class: " + str(ip.tc))
    print ("\t Source: " + str(ip.src))
    print ("\t Destination: " + str(ip.dst))

# Display the IPv6 header with matched fields in red
def displayMatchedIPv6(ip, rule):
    print ("[IPv6]")
    print ("\t Version: " + str(ip.version))

    if (rule.srcIp.ipn.num_addresses == 1):
        print (RED + "\t Source: " + str(ip.src) + ENDC)
    else:
        print ("\t Source: " + str(ip.src))

    if (rule.dstIp.ipn.num_addresses == 1):
        print (RED + "\t Destination: " + str(ip.dst) + ENDC)
    else:
        print ("\t Destination: " + str(ip.dst))

# Display the TCP header
def displayTCP(tcp):
    print ("[TCP]")
    print ("\t Source Port: " + str(tcp.sport))
    print ("\t Destination Port: " + str(tcp.dport))
    print ("\t Sequence Number: " + str(tcp.seq))
    print ("\t Acknowledgment Number: " + str(tcp.ack))
    print ("\t Data Offset: " + str(tcp.dataofs))
    print ("\t Reserved: " + str(tcp.reserved))
    print ("\t Flags: " + tcp.underlayer.sprintf("%TCP.flags%"))
    print ("\t Window Size: " + str(tcp.window))
    print ("\t Checksum: " + str(tcp.chksum))
    if (tcp.flags & URG):
        print ("\t Urgent Pointer: " + str(tcp.window))
    if (tcp.dataofs > 5):
        print ("\t Options: " + str(tcp.options))

# Display the TCP header with matched fields in red
def displayMatchedTCP(tcp, rule):
    print ("[TCP]")
    if (hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1):
        print (RED + "\t Source Port: " + str(tcp.sport) + ENDC)
    else:
        print ("\t Source Port: " + str(tcp.sport))
    
    if (hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1):
        print (RED + "\t Destination Port: " + str(tcp.dport) + ENDC)
    else:
        print ("\t Destination Port: " + str(tcp.dport))
    
    if (hasattr(rule, "seq")):
        print (RED + "\t Sequence Number: " + str(tcp.seq) + ENDC)
    else:
        print ("\t Sequence Number: " + str(tcp.seq))
    
    if (hasattr(rule, "ack")):
        print (RED + "\t Acknowledgment Number: " + str(tcp.ack) + ENDC)
    else:
        print ("\t Acknowledgment Number: " + str(tcp.ack))
    
    print ("\t Data Offset: " + str(tcp.dataofs))
    print ("\t Reserved: " + str(tcp.reserved))
    if (hasattr(rule,"flags")):
        print (RED + "\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%") + ENDC)
    else:
        print ("\t Flags:" + tcp.underlayer.sprintf("%TCP.flags%"))
    
    print ("\t Window Size: " + str(tcp.window))
    print ("\t Checksum: " + str(tcp.chksum))
    if (tcp.flags & URG):
        print ("\t Urgent Pointer: " + str(tcp.window))
    if (tcp.dataofs > 5):
        print ("\t Options: " + str(tcp.options))

# display ARP header
def displayMatchedARP(arp, rule):
    print ("[ARP]")
    print ("\t Hardware Type: " + str(arp.hwtype))
    print ("\t IP Type: " + str(arp.ptype))
    if (hasattr(rule, "op")):
        if(arp.op == 1):
            print (RED + "\t Request Type: who-has" + ENDC)
        else:
            print (RED + "\t Request Type: is-at" + ENDC)
    print ("\t Hardware Source: " + str(arp.hwsrc))
    print ("\t Hardware Destination: " + str(arp.hwdst))
    print ("\t IP source: " + str(arp.psrc))
    print ("\t IP Destination: " + str(arp.pdst))
     
# display UDP header
def displayUDP(udp):
    print ("[UDP]")
    print ("\t Source Port: " + str(udp.sport))
    print ("\t Destination Port: " + str(udp.dport))
    print ("\t Length: " + str(udp.len))
    print ("\t Checksum: " + str(udp.chksum))

# Display the UDP header with matched fields in red
def displayMatchedUDP(udp, rule):
    print ("[UDP]")
    if (hasattr(rule.srcPorts, "listPorts") and len(rule.srcPorts.listPorts) == 1):
        print (RED + "\t Source Port: " + str(udp.sport) + ENDC)
    else:
        print ("\t Source Port: " + str(udp.sport))
    
    if (hasattr(rule.dstPorts, "listPorts") and len(rule.dstPorts.listPorts) == 1):
        print (RED + "\t Destination Port: " + str(udp.dport) + ENDC)
    else:
        print ("\t Destination Port: " + str(udp.dport))
    print ("\t Checksum: " + str(udp.chksum))


# Display the payload of a packet
def displayPayload(pkt):
    if (pkt.payload):
        data = str(pkt.payload)
        lines = data.splitlines()
        out = ""
        for line in lines:
            out += "\t" + line + "\n"
        print (out)


# Display the TCP payload with matched fields in red
def displayMatchedTCPPayload(tcp, rule):
    print ("[TCP Payload]")

    if (hasattr(rule, "http_request")):
        print (RED + "HTTP Request: " + str(rule.http_request) + ENDC)

    if (hasattr(rule, "http_uri")):
        print (RED + "HTTP URI: " + str(rule.http_uri) + ENDC)

    if (hasattr(rule, "content") and tcp.payload):
        data = tcp.payload
        if isinstance(data, Padding):
            # Handle Padding payload
            data = str(data.original)
        elif isinstance(data, Raw):
            # Handle Raw payload
            data = tcp.payload.getlayer(Raw).load.decode('utf-8', 'ignore')
        else:
            # Handle other payload types as needed
            data = str(data)
        # add red color when content found in the string
        data = unquote(data)
        data = data.lower()
        data = re.sub(unquote(rule.content), RED + rule.content + ENDC, data)
        lines = data.splitlines()
        out = ""
        for line in lines:
            out += "\t" + line + "\n"
        print (out)
    else:
        displayPayload(tcp)

# Whole matched packet form IP to app layer
def printMatchedPacket(pkt, rule):
    if (IP in pkt):
        # IP Header
        displayMatchedIP(pkt[IP], rule)
    elif (IPv6 in pkt):
        displayMatchedIPv6(pkt[IPv6])
    if (TCP in pkt):
        # TCP Header
        displayMatchedTCP(pkt[TCP], rule)
        # Payload
        displayMatchedTCPPayload(pkt[TCP], rule)
    elif (UDP in pkt):
        displayMatchedUDP(pkt[UDP], rule)
        print ("[UDP Payload]")
        displayPayload(pkt[UDP])
    if (ARP in pkt):
        displayMatchedARP(pkt[ARP], rule)

# Display the whole packet from IP to Application layer without matching
def printPacket(pkt):
    if (IP in pkt):
        displayIP(pkt[IP])
    elif (IPv6 in pkt):
        displayIPv6(pkt[IPv6])
    if (TCP in pkt):
        displayTCP(pkt[TCP])
        print ("[TCP Payload]")
        displayPayload(pkt[TCP])
    elif (UDP in pkt):
        displayUDP(pkt[UDP])
        print ("[UDP Payload]")
        displayPayload(pkt[UDP])