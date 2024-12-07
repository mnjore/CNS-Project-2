from SIDS.Action import *
from SIDS.Protocol import *
from SIDS.IPs import *
from SIDS.Ports import *
from SIDS.Rule import *

def read(file_name):

    # Initialize an empty list to store the parsed rules
    l = list()

    # Open the rule file in read mode
    with open (file_name, 'r') as f:
        error = 0
        for line in f:
            try:
                # Attempt to create a Rule object from the line
                rule = Rule(line)
                # If successful, append the rule to the list
                l.append(rule)
            except ValueError as e:
                # If a ValueError occurs (invalid rule format), increment the error count
                error += 1
                # Print the rule that caused the error for debugging
                print(rule)
                
    return l,error