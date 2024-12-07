#A class which isa  port set; a list, a range or 'any'
class Ports:
    def __init__(self,string):
        """
        Initialize the Ports object with a given string.
        
        - "any": Matches any port.
        - Range: Specified as "low:high", e.g., "30:100".
          - A missing lower or upper bound can be indicated with ":", e.g., ":100" or "30:".
        - List: A comma-separated list of ports, e.g., "20,30,40".
        - Single port: A single value, e.g., "32".
        """
        try:
            # any port
            if (string == "any"):
                self.type = "any"

            # range of ports
            elif(':' in string):
                self.type = "range"
                strs = string.split(':')

                if(string[0] == ":"):
                     # No lower bound specified
                     self.lowPort = -1
                     self.highPort = int(strs[1])
                elif(string[len(string)-1] == ":"):
                    # No upper bound specified.
                    self.lowPort = int(strs[0])
                    self.highPort = -1
                else:
                # Both bounds specified.
                    self.lowPort = int(strs[0])
                    self.highPort= int(strs[1])

            elif(',' in string):
                # Represents a list of ports.
                self.type = "list"
                self.listPorts = list()
                strs = string.split(',')
                for s in strs:
                    self.listPorts.append(int(s))
            else:
                # Represents a single port as a list with one element.
                self.type = "list"
                self.listPorts = list()
                self.listPorts.append(int(string))

        # Handle incorrect input strings.        
        except ValueError as e:
            print(f"Incorrect input string with value {e}.")

    # Check if a given port is part of the defined set.
    def contains(self, port):
        if(self.type == "any"):
            return True
        elif(self.type == "range"):
            # No lower bound, only check upper bound.
            if (self.lowPort == -1):
                return port <= self.highPort
            # No upper bound, only check lower bound.
            elif(self.highPort == -1):
                return port >= self.lowPort
            # Check if the port is within the range.
            else:
                return self.lowPort <= port and port <= self.highPort
        
        # Check if the port is in the list.
        elif (self.type == "list"):
            return port in self.listPorts

    # Represent the Ports object as a string.
    def __repr__(self):
        if(self.type == "any"):
            return "any"
        elif(self.type == "range"):
            if(self.lowPort == -1):
                return ":" + str(self.highPort)
            elif(self.highPort == -1):
                return str(self.lowPort) + ":"
            else:
                return str(self.lowPort) + ":" + str(self.highPort)
        elif(self.type == "list"):
            return self.listPorts.__repr__()