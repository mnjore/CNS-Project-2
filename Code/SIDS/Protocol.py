from enum import Enum

class Protocol(Enum):
    # Each protocol is assigned a value
    TCP = 1
    UDP = 2
    HTTP = 3
    ARP = 4
    IPv6 = 5

# Returning Protocol corresponding to string
def protocol(istr):

    pro = istr.lower().strip()
    if(pro == "tcp"):
        return Protocol.TCP
    
    elif(pro == "udp"):
        return Protocol.UDP
    
    elif(pro == "http"):
        return Protocol.HTTP
    
    elif(pro == "arp"):
        return Protocol.ARP

    elif(pro == "ipv6"):
        return Protocol.IPv6
    
    else:
        raise ValueError(f"Invalid rule for protocol : {istr}.")