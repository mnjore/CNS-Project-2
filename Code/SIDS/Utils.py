from enum import Enum
from scapy.all import *
import re

# List of common HTTP methods
HTTPcommands = ["GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "CONNECT", "PATCH"]

# List of protocols to detect URLs
HTTPUrls = ["http://", "https://"]

# Keywords related to SQL queries
Sql = ["select", "and", "or"]

# Function to determine if a packet contains HTTP data
def isHTTP(pkt):
    # Check if the packet contains a TCP layer with a payload
    if (TCP in pkt and pkt[TCP].payload):
        data = pkt[TCP].payload
        # Handle various payload types
        if isinstance(data, Padding):
            # Handle Padding payload
            data = str(data.original)
        elif isinstance(data, Raw):
            # Handle Raw payload
            data = str(data.load)
        else:
            # Handle other payload types as needed
            data = str(data)

        # Search for the literal "HTTP" in the payload
        match = re.search(r"\bHTTP\b", data)
        if match:
            # HTTP data found
            return True
        else:
            # If not, check for HTTP methods (GET, POST, etc.)
            for word in HTTPcommands:
                word = r'\b{}\b'.format(re.escape(word))
                match = re.search(word.rstrip(), data)
                if match:
                    # HTTP found
                    return True
                else:
                    return False
    else:
        return False

# Check if the given packet contains an HTTP or HTTPS URL
def http_url(pkt):
    # Check if the packet has a TCP layer with a payload
    if(TCP in pkt and pkt[TCP].payload):
        data = pkt[TCP].payload

        # Handle various payload types
        if isinstance(data, Padding):
            # Handle Padding payload
            data = str(data.original)
        elif isinstance(data, Raw):
            # Handle Raw payload
            data = str(data.load)
        else:
            # Handle other payload types as needed
            data = str(data)

        # Search for URLs starting with http:// or https://
        for word in HTTPUrls:
            word = r'\b{}\b'.format(re.escape(word))
            match = re.search(word, data)
            if match:
                # print(data,";",word)
                # sys.exit(0)
                return True #URL found
            else:
                return False
    else: 
        return False