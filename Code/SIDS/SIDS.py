from scapy.all import *
from SIDS.Rule import *

# class responsible for sniffing and detecting suspect packet
class Sniff():
    # Initializes the Sniff object with a list of rules to evaluate against packets
    def __init__(self, ruleList):
        self.ruleList = ruleList

    # Handles each incoming packet and checks it against the list of rules
    def inPacket(self, pkt):
        print ("Checking rule for packet...")
        for rule in self.ruleList:
            # Check if the packet matches the current rule
            matched = rule.match(pkt)
            if (matched):
                # Print the message associated with the matched rule
                # and return ture since match was found
                print(rule.getMatchedPrintMessage(pkt))
                return True