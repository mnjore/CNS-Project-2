from ipaddress import *

# A class that simplifies working with IP addresses and CIDR blocks.
class IPs:

    # Initialize the IPs object by parsing the input strin
    def __init__(self, string):
        try:
            if string.lower().rstrip() == "any":
                # Represents any IPv4 address (0.0.0.0/0).
                self.ipn = ip_network(u'0.0.0.0/0')
            elif string.lower().rstrip() == "any_ipv6":
                # Represents any IPv6 address (::/0).
                self.ipn = IPv6Network(u'::/0')
            else:
                # Split the string into address and subnet mask
                ips = string.split("/")
                if len(ips) >= 2:
                    block = int(ips[1])
                    if ":" in ips[0]:  # Checking if it's an IPv6 address
                        self.ipn = IPv6Network(ips[0] + "/" + str(block))
                    else:
                        self.ipn = ip_network(ips[0] + "/" + str(block))
                else:
                     # If no subnet mask is provided, default to a /128 for IPv6 or /32 for IPv4.
                    if ":" in ips[0]:  # Checking if it's an IPv6 address
                        self.ipn = IPv6Network(ips[0] + "/128")
                    else:
                        self.ipn = ip_network(ips[0] + "/32")

        except ValueError as e:
            print(f"Incorrect string due to {e}.")
    
    def contains(self, ip):
        #Check if the ip is correct, return True if it is
        return (ip in self.ipn)

    def __repr__(self):
        #Return tring representation in String
        return self.ipn.__repr__()