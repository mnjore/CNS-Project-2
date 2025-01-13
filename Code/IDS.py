from scapy import *
import argparse
import logging
from datetime import datetime
from SIDS.RuleRead import read
from AIDS.Anomaly import *
import keyboard

# defining colors
RED = '\033[91m'
BLUE = '\033[34m'
GREEN = '\033[32m'
ENDC = '\033[0m'

def main(filename):
    
    # get current date and time for logging
    now = datetime.now().strftime("%d-%m-%Y %H-%M-%S")

    logging.basicConfig(filename= "logs\\NIDS " + str(now) + '.log',level=logging.INFO)

    print ("\nIDS started.\n")

    # Read the rule file
    print ("Reading rule file...\n")
    global ruleList
    ruleList, errorCount = read(filename)
    print ("Finished reading rule file.\n")

    # get the result of rule reading
    if (errorCount == 0):
        print ("All (" + str(len(ruleList)) + ") rules have been correctly read.\n")
    else:
        print (str(len(ruleList)) + " rules have been correctly read.")
        print (str(errorCount) + " rules have errors and could not be read.")

    sniffer = detect(ruleList)

    # function to stop the sniffer when the 'esc' key is pressed
    def on_esc(event):
        sniffer.stop()
        print(ENDC, "\nESC pressed. Stopping IDS.\n")
        
    # 'esc' key event handler
    keyboard.on_press_key("esc", on_esc)

    sniffer.start()

if __name__ == '__main__':

    # argument parser to handle file path input
    parser = argparse.ArgumentParser(description='Simple NIDS')
    parser.add_argument('-f', '--filename', help='Path to the rule file', default=r'C:\Users\LENOVO\OneDrive\Documents\U\4\CNS Project 2\Intrusion-Detection-System-main\Intrusion-Detection-System-main\IDS_Final\SIDS\rules.txt')
    args = parser.parse_args()
    
    ruleList = list()
    main(args.filename)