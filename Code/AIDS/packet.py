from scapy.all import *
import psutil

class packetDetails:
    # Initializes object to store detailed packet information such as source, destination, protocol etc. 
    def __init__(self):
        self.src = ""  # Source IP address
        self.dest = ""  # Destination IP address
        self.src_port = 0  # Source port number
        self.dest_port = 0  # Destination port number
        self.protocol = ''  # Protocol used (TCP, UDP, etc.)
        self.timestamp = 0  # Timestamp of the packet

        self.PSH_flag = False
        self.FIN_flag = False
        self.SYN_flag = False
        self.ACK_flag = False
        self.URG_flag = False
        self.RST_flag = False
        self.CWE_flag = False
        self.ECE_flag = False

        self.payload_bytes = 0  # Size of the payload in bytes
        self.header_bytes = 0  # Size of the header in bytes
        self.packet_size = 0  # Total packet size
        self.win_bytes = 0  # Window size in bytes
        self.mss = 0  # Maximum segment size (not used currently)
        self.tos = 0  # Type of service
        self.offset = 0  # Fragment offset


        self.fwd_id = ""  # Forward flow ID
        self.bwd_id = ""  # Backward flow ID

        self.pid = None  # Process ID related to the packet
        self.p_name = ''  # Process name related to the packet

    # sets the source IP address from the packet based on the layer type
    def setSrc(self, pkt):
        if ARP in pkt:
            self.src = pkt.getlayer(ARP).psrc
        if IP in pkt:
            self.src = pkt.getlayer(IP).src
        if IPv6 in pkt:
            self.src = pkt.getlayer(IPv6).src

    # Returns the source IP address.
    def getSrc(self):
        return self.src

    # Sets destination IP addr from packet based on the layer type
    def setDest(self, pkt):
        if ARP in pkt:
            self.dest = pkt.getlayer(ARP).pdst
        if IP in pkt:
            self.dest = pkt.getlayer(IP).dst
        if IPv6 in pkt:
            self.dest = pkt.getlayer(IPv6).dst

    # Returns the destination IP address.
    def getDest(self):
        return self.dest

    #  Sets the source port number from the packet and attempts to match it with a process using psutil
    def setSrcPort(self, pkt):

        if pkt.haslayer(TCP):
            self.src_port = pkt.getlayer(TCP).sport
        
        elif pkt.haslayer(UDP):
            self.src_port = pkt.getlayer(UDP).sport

        else:
            self.src_port = 0

        # Attempt to get the PID and process name if not already set
        if self.pid is None and self.p_name == '':
            connections = psutil.net_connections()

            for con in connections:
                if(con.laddr.port -  self.src_port == 0.0) or (con.laddr.port - self.dest_port == 0.0):
                    self.pid = con.pid
                    self.p_name = psutil.Process(con.pid).name()

    # Returns the source port number
    def getSrcPort(self):
        return self.src_port
    
    # Sets the destination port number from the packet and attempts to match it with a process using psutil
    def setDestPort(self, pkt):

        if pkt.haslayer(TCP):
            self.dest_port = pkt.getlayer(TCP).dport

        elif pkt.haslayer(UDP):
            self.dest_port = pkt.getlayer(UDP).dport

        else:
            self.dest_port = 0
        
        if self.pid  is None and self.p_name == '':
            connections = psutil.net_connections()
            for con in connections:
                if(con.laddr.port - self.src_port == 0.0) or (con.laddr.port - self.dest_port == 0.0):
                    self.pid = con.pid
                    self.p_name = psutil.Process(con.pid).name()

    # Returns the PID of the process related to the packet
    def getPID(self):
        return self.pid

    # Returns the name of the process related to the packet
    def getPName(self):
        return self.p_name

    # Returns the destination port number
    def getDestPort(self):
        return self.dest_port

    # Sets the protocol type
    def setProtocol(self, pkt):

        if pkt.haslayer(TCP):
            self.protocol = 'TCP'

        if pkt.haslayer(UDP):
            self.protocol = 'UDP'

        if pkt.haslayer(ICMP):
            self.protocol = 'ICMP'

        if pkt.haslayer(ARP):
            self.protocol = 'ARP'

        if pkt.haslayer(IPv6):
            self.protocol = 'IPv6'

        if pkt.haslayer(IP) and not (pkt.haslayer('TCP') or pkt.haslayer('UDP')) :
            self.protocol = 'Routing'

    # Returns the protocol type
    def getProtocol(self):
        return self.protocol

    # Sets the timestamp of the packet
    def setTimestamp(self, pkt):
        self.timestamp = pkt.time
    
    def getTimestamp(self):
        return self.timestamp

    # Sets various flags
    def setFlag(self, pkt):
        if pkt.haslayer(TCP):
            self.tcp_flags = []
            self.tcp_flags.append(pkt[TCP].flags)
            # print("Flags:",self.tcp_flags)
            for flag in self.tcp_flags:
                if 'P' in flag:
                    self.PSH_flag = True
                if 'F' in flag:
                    self.FIN_flag = True
                if 'S' in flag:
                    self.SYN_flag = True
                if 'A' in flag:
                    self.ACK_flag = True
                if 'U' in flag:
                    self.URG_flag = True
                if 'R' in flag:
                    self.RST_flag = True
                if 'C' in flag:
                    self.CWE_flag = True
                if 'E' in flag:
                    self.ECE_flag = True

    # Returns the PSH flag status
    def getPSHFlag(self):
        return self.PSH_flag   
    
    def getFINFlag(self):
        return self.FIN_flag

    def getSYNFlag(self):
        return self.SYN_flag
            
    def getRSTFlag(self):
        return self.RST_flag

    def getACKFlag(self):
        return self.ACK_flag

    def getURGFlag(self):
        return self.URG_flag

    def getCWEFlag(self):
        return self.CWE_flag
    
    def getECEFlag(self):
        return self.ECE_flag

    # Sets the payload size in bytes based on the packet type
    def setPayloadBytes(self, pkt):
        if pkt.haslayer(TCP):
            self.payload_bytes = len(pkt[TCP].payload)
        if pkt.haslayer(UDP):
            self.payload_bytes = len(pkt[UDP].payload)

    # Returns the payload size in bytes
    def getPayloadBytes(self):
        return self.payload_bytes

    # Sets the header size in bytes based on the packet type 
    def setHeaderBytes(self, pkt):
        if pkt.haslayer(TCP):
            self.header_bytes = len(pkt[TCP]) - len(pkt[TCP].payload)
        if pkt.haslayer(UDP):
            self.header_bytes = len(pkt[UDP]) - len(pkt[UDP].payload)

    def getHeaderBytes(self):
        return self.header_bytes

    # Sets the total packet size based on the packet type
    def setPacketSize(self, pkt):
        if pkt.haslayer(TCP):
            self.packet_size = len(pkt[TCP])
        if pkt.haslayer(UDP):
            self.packet_size = len(pkt[UDP])

    def getPacketSize(self):
        return self.packet_size

    # Sets the window size in bytes from the TCP packet
    def setWinBytes(self, pkt):
        if pkt.haslayer(TCP):
            self.win_bytes = pkt[0].window

    def getWinBytes(self):
        return self.win_bytes
    
    # Returns the Type of Service (ToS) value from the IP header
    def getTos(self):
        return self.tos

    # Sets the ToS field from the IP header, which defines the packet's priority
    def setTos(self, pkt):
        if pkt.haslayer(IP):
            self.tos = int(pkt[IP].tos)
    
    # Returns the fragment offset from the IP header. This is used in fragmented IP packets
    def getOffset(self):
        return self.offset

    # Sets the fragment offset for fragmented IP packets
    def setOffset(self, pkt):
        if pkt.haslayer(IP):
            self.offset = int(pkt[IP].frag)

    # Sets unique flow IDs based on the combination of source and destination IPs, ports, and protocol
    # This is used to track individual flows
    def setID(self, pkt):
        self.fwd_id = self.src + "-" + self.dest + "-" + \
                        str(self.src_port) + "-" + str(self.dest_port) + "-" + self.protocol

        self.bwd_id = self.dest + "-" + self.src + "-" + \
                        str(self.dest_port) + "-" + str(self.src_port) + "-" + self.protocol

    # Returns the forward flow ID
    def getFwdID(self):
        return self.fwd_id

    # Returns the backward flow ID
    def getBwdID(self):
        return self.bwd_id 