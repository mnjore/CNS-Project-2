from ipaddress import *
from scapy.all import *
from SIDS.Action import Action
from SIDS.Protocol import *
from SIDS.IPs import *
from SIDS.Ports import *
from SIDS.Utils import *
from SIDS.Print_Packet import *
import logging
from urllib.parse import unquote
from io import StringIO

class Rule:
    #Represents a SIDS rule
    def __init__(self, string):

        self.string = string
        string = string.strip() # Strips leading/trailing whitespace
        strs = string.split(' ') # Splits rule string into parts
        self.counts={} # Dictionary to track rule match counts for threshold checks
        
        self.timestamp = time.time() # Timestamp for threshold tracking

        # Ensures the rule has the required number of parts
        if (len(strs) >= 7):

            # Parse the action (e.g., ALERT, PASS)
            self.action = Action.action(strs[0])
             # Parse the protocol (e.g., TCP, UDP)
            self.protocol = protocol(strs[1])
            
             # Parse source IP and handle errors if invalid
            try:
                self.srcIp = IPs(strs[2])
            except ValueError as e:
                print(f"Invalid rule with incorrect source ip with error {e}.")
            
            # Parse source port and handle errors if invalid
            try:
                self.srcPorts = Ports(strs[3])
            except ValueError as e:
                print(f"Invalid rule with incorrect source port with error {e}.")
            
            # Parse destination IP and handle errors if invalid
            try:
                self.dstIp = IPs(strs[5])
            except ValueError as e:
                print(f"Invalid rule with incorrect destination ip with error {e}.")
            
        
            # Parse destination port and handle errors if invalid
            try:
                self.dstPorts = Ports(strs[6])
            except ValueError as e:
                print(f"Invalid rule with incorrect destination ip with error {e}.")

            # Additional options
            strs = string.split('(')
            if (len(strs) >= 2):
                # remove trailing ')' if present
                if (strs[-1][-1] == ')'):
                    strs[-1] = strs[-1][:-1]

                # options may be present, split by semicolon
                opts = strs[1].split(';')

                for opt in opts:
                    if (opt == "by_dstport"):
                        self.by_dstport = True
                    if(opt == "http_body"):
                        self.http_body = True
                    kv = opt.split(':',1)
                    if(len(kv) >= 2):
                        option = kv[0].strip()
                        value = kv[1].strip()
                        if(option == "msg"):
                            self.msg = value
                        elif(option == "tos"):
                            self.tos = int(value)
                        elif (option == "len"):
                            self.len = int(value)
                        elif (option == "offset"):
                            self.offset = int(value)
                        elif (option == "seq"):
                            self.seq = int(value)
                        elif (option == "ack"):
                            self.ack = int(value)
                        elif (option == "flags"):
                            self.flags = value
                        elif (option == "op"):
                            self.op = int(value)
                        elif (option == "id"):
                            self.id = int(value)
                        elif (option == "threshold"):
                            self.threshold = value
                            self.ths = self.threshold.split(',')
                            for th in self.ths:
                                self.th = th.strip()
                                kv = self.th.split(' ', 1)
                                if(len(kv) >= 2):
                                    option = kv[0].strip()
                                    value = kv[1].strip()
                                    if(option == "count"): 
                                        self.count = int(value)   
                                    if(option == "seconds"):
                                        self.seconds = int(value)
                        elif (option == "http_request"):
                            self.http_request = value
                            if (self.http_request.endswith('"')):
                                self.http_request = self.http_request[:-1]
                            if (self.http_request.startswith('"')):
                                self.http_request = self.http_request[1:]
                                
                        elif (option == "http_url"):
                            self.http_url = value
                            if (self.http_url.endswith('"')):
                                self.http_url = self.http_url[:-1]
                            if (self.http_url.startswith('"')):
                                self.http_url = self.http_url[1:]

                        elif (option == "content"):
                            self.content = value
                            # remove starting and ending ["]
                            if (self.content.endswith('"')):
                                self.content = self.content[:-1]
                            if (self.content.startswith('"')):
                                self.content = self.content[1:]
                        else:
                            raise ValueError("Invalid rule with incorrect option : '" + option + "'.")

                    
        else:
            raise ValueError("Invalid rule : a rule must include mandatory elements : action, protocol, src_ips, src_ports -> dst_ips, dst_ports")

    def __repr__(self):
        # Returns the string representing the Rule
        return self.string

    def match(self, pkt):
        # Returns True if the rule is completeley matched by given packet
        # Check protocol, IPs, ports, and options
        if not self.checkProtocol(pkt) or not self.checkIps(pkt) or not self.checkPorts(pkt) or not self.checkOptions(pkt):
            return False

        # count the matched rule for threshold
        dst_ip = self.dst_Ip
        if dst_ip not in self.counts:
            self.counts[dst_ip] = {}
            self.counts[dst_ip][self.id] = 1
        elif self.id not in self.counts[dst_ip]:
            self.counts[dst_ip][self.id] = 1
        else:
            self.counts[dst_ip][self.id] += 1
        # check threshold
        if (not self.checkThreshold(pkt)):
            return False
            
        return True

    def checkProtocol(self, pkt):
        # Returns True if the rule concerns packet protocol
        f = False
        if (self.protocol == Protocol.TCP and TCP in pkt):
            f = True
        elif (self.protocol == Protocol.UDP and UDP in pkt):
            f = True
        elif (self.protocol == Protocol.ARP and ARP in pkt):
            f = True
        elif (self.protocol == Protocol.HTTP and TCP in pkt):
            if (isHTTP(pkt)):
                f = True
        elif (self.protocol == Protocol.IPv6 and IPv6 in pkt):
            f = True
        return f

    def checkIps(self, pkt):
        # Returns True if the rule's IPs concern the pkt IPs
        f = False
        if (ARP in pkt):
            self.src_Ip = pkt[ARP].psrc
            self.dst_Ip = pkt[ARP].pdst
            ipSrc = ip_address(str(self.src_Ip))
            ipDst = ip_address(str(self.dst_Ip))
            if (self.srcIp.contains(ipSrc) and self.dstIp.contains(ipDst)):
                # ipSrc and ipDst match rule's source and destination ips
                f = True
            else:
                f = False
        elif (IPv6 in pkt):
            self.src_Ip = pkt[IPv6].src
            self.dst_Ip = pkt[IPv6].dst
            ipSrc = ip_address(str(self.src_Ip))
            ipDst = ip_address(str(self.dst_Ip))
            
            if (self.srcIp.contains(ipSrc) and self.dstIp.contains(ipDst)):
                # ipSrc and ipDst match rule's source and destination ips
                f = True
            else:
                f = False
        else:
            self.src_Ip = pkt[IP].src
            self.dst_Ip = pkt[IP].dst
            ipSrc = ip_address(str(self.src_Ip))
            ipDst = ip_address(str(self.dst_Ip))
            if (self.srcIp.contains(ipSrc) and self.dstIp.contains(ipDst)):
                # ipSrc and ipDst match rule's source and destination ips
                f = True
            else:
                f = False
        return f

    def checkPorts(self, pkt):
        # Returns True if the rule's Ports concern packet's Ports
        f = False
        if (ARP in pkt):
            self.srcPort = 0
            self.dstPort = 0
            if (self.srcPorts.contains(self.srcPort) and self.dstPorts.contains(self.dstPort)):
                f = True
        if (UDP in pkt):
            self.srcPort = pkt[UDP].sport
            self.dstPort = pkt[UDP].dport
            if (self.srcPorts.contains(self.srcPort) and self.dstPorts.contains(self.dstPort)):
                f = True
        elif (TCP in pkt):
            self.srcPort = pkt[TCP].sport
            self.dstPort = pkt[TCP].dport
            if (self.srcPorts.contains(self.srcPort) and self.dstPorts.contains(self.dstPort)):
                f = True
        else:
            self.srcPort = 0
            self.dstPort = 0
        return f

    def checkOptions(self, pkt):
        # Return True if and only if all options are matched
        if (hasattr(self, "op")):
            if (ARP in pkt):
                if(self.op != int(pkt[ARP].op)):
                    return False
            else:
                return False
        if (hasattr(self, "tos")):
            if (IP in pkt):
                if (self.tos != int(pkt[IP].tos)):
                    return False
            else:
                return False

        if (hasattr(self, "len")):
            if (IP in pkt):
                if (self.len != int(pkt[IP].ihl)):
                    return False
            else:
                return False

        if (hasattr(self, "offset")):
            if (IP in pkt):
                if (self.offset != int(pkt[IP].frag)):
                    return False
            else:
                return False

        if (hasattr(self, "seq")):
            if (TCP not in pkt):
                return False
            else:
                if (self.seq != int(pkt[TCP].seq)):
                    return False

        if (hasattr(self, "ack")):
            if (TCP not in pkt):
                return False
            else:
                if (self.ack != int(pkt[TCP].ack)):
                    return False
        

        if (hasattr(self, "flags")):
            # match if and only if the received packet has all the rule flags set
            if (TCP not in pkt):
                return False
            else:
                for c in self.flags:
                    pktFlags = pkt[TCP].underlayer.sprintf("%TCP.flags%")
                    if (c not in pktFlags):
                        return False


        if (hasattr(self, "http_request")):
            if (not isHTTP(pkt)):
                return False
            elif (TCP in pkt and pkt[TCP].payload and not isHTTP(pkt)):
                data = pkt[TCP].payload
                if isinstance(data, Padding):
                    # Handle Padding payload
                    data = str(data.original)
                elif isinstance(data, Raw):
                    # Handle Raw payload
                    data = str(data.load)
                else:
                    # Handle other payload types as needed
                    data = str(data)
                self.http_request = r'\b{}\b'.format(re.escape(self.http_request))
                match = re.search(self.http_request, data)
                if not match:
                    return False


        if (hasattr(self, "http_url")):

            if (not http_url(pkt)):
                    return False
            elif (TCP in pkt and pkt[TCP].payload and not http_url(pkt)):
                data = pkt[TCP].payload
                if isinstance(data, Padding):
                    # Handle Padding payload
                    data = str(data.original)
                elif isinstance(data, Raw):
                    # Handle Raw payload
                    data = str(data.load)
                else:
                    # Handle other payload types as needed
                    data = str(data)
                self.http_url = r'\b{}\b'.format(re.escape(self.http_url))
                match = re.search(self.http_url, data)
                if not match:
                    return False

        if (hasattr(self, "http_body")):
            if (http_ur(pkt)) and isHTTP(pkt):
                return False

        if (hasattr(self, "content")):
            payload = None
            if (TCP in pkt):
                payload = pkt[TCP].payload
            elif (UDP in pkt):
                payload = pkt[UDP].payload
            if (payload):
                if isinstance(payload, Padding):
                # Handle Padding payload
                    payload = str(payload.original)
                elif isinstance(payload, Raw):
                    # Handle Raw payload
                    payload = pkt.getlayer(Raw).load.decode('utf-8', 'ignore')
                    
                else:
                    # Handle other payload types as needed
                    payload = str(payload)
                payload = unquote(payload)
                self.content = unquote(self.content)
                if (str(self.content).lower() not in str(payload).lower()):
                    return False
            else:
                return False
        return True

    # Check if the rule has a threshold attribute
    def checkThreshold(self, pkt):
        if(hasattr(self, "threshold")):
            # print("count:,",self.counts)
            # print(self.timestamp)
            for ip in self.counts:
                for value in self.counts[ip]:
                    # print("great: ", self.counts[ip][value],", ",self.count)
                    # print(time.time() - self.timestamp)
                    # Check if the count for the current IP and value exceeds the threshold
                    if self.count > self.counts[ip][value] and (time.time() - self.timestamp) < self.seconds:
                        # print("less :",self.counts[ip][value])
                        # If the threshold is exceeded, return False
                        return False
                    # Reset the timestamp and count for this IP-value pair
                    else: 
                        self.timestamp = time.time()
                        self.counts[ip][value] = 0
                        # Allow the packet through by returning True
                        return True
        return True
                    
    # Generates and logs a message when a rule is matched
    def getMatchedPrintMessage(self, pkt):
        # Return the message in the console
        msg = ""
        if (self.action == Action.ALERT):
            # Create a red-highlighted alert message
            msg += RED + "ALERT "
            # Append the specific rule message if it exists
            if hasattr(self, "msg"):
                msg += self.msg
            msg += "\n" + ENDC
            # Include the matched rule information
            msg += "Rule matched : " + str(self) + "\n"
            # Redirect stdout to a StringIO object
            output = StringIO()
            sys.stdout = output
            # Call the function that prints packet details
            printMatchedPacket(pkt, self)
            # Retrieve the captured output as a string
            printed_string = output.getvalue()
            # Reset stdout to its original state
            sys.stdout = sys.__stdout__

             # Append the captured output to the message
            msg += printed_string
            # Log the message as a critical alert
            logging.critical(msg)

        # If the rule action is to PASS (mark as benign)
        elif (self.action == Action.PASS):
            msg += GREEN + "BENIGN "
            # Include the rule information and packet details
            msg += "\n" + ENDC + str(self)
            msg += str(self.protocol) + " " + str(self.src_Ip) + " " + str(self.srcPort) + " -> " + str(self.dst_Ip) + " " + str(self.dstPort) + "\n"
            # Log the message as benign
            logging.info(msg)

        return msg