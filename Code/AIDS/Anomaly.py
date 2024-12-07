from AIDS.flow import Flow
from AIDS.packet import packetDetails
import logging
from threading import Thread
from scapy.sendrecv import sniff
import numpy as np
import csv 
import traceback

import pandas as pd
import joblib
from SIDS.SIDS import Sniff

# defining colors
RED = '\033[91m'
ENDC = '\033[0m'
GREEN = '\033[32m'

class detect(Thread):
    
    def __init__(self, rulelist):
        Thread.__init__(self)
        self.stopped = False
        self.flow = None
        self.rulelist = rulelist 
        self.csv_file = 'AIDS\\data\\network_data_1.csv' # csv file for storing network data

        # writing header to the CSV file
        with open(self.csv_file, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['Flag','Duration','protocol','src_ip', 'src_port', 'dst_ip', 'dst_port', 'Predicted_Value', 'Real_Value'])
        
        self.current_flows = {}
        self.FlowTimeout = 600

        # loading pre-trained ML model
        model_filename = "AIDS\\Model\\xgboost_model_8.pkl"
        self.model = joblib.load(model_filename)

        # loading the label encoder for translating outputs
        encoder_filename = "AIDS\\Model\\label_encoder_1.pkl"
        self.label_encoder = joblib.load(encoder_filename)

        # open a file for writing predictions
        f = open('AIDS\\data\\predict.txt','w', encoding='utf-8')   

    # func that sets the stopped flag to True to stop sniffing
    def stop(self):
        self.stopped = True

    def stopfilter(self, x):
        return self.stopped
    
    # function to make predictions
    def predict(self,data):
        
        # define columns for the feature set
        cols = ['Destination Port', 'Flow Duration', 'Total Fwd Packets',
            'Total Backward Packets', 'Total Length of Fwd Packets',
            'Total Length of Bwd Packets', 'Fwd Packet Length Max',
            'Fwd Packet Length Min', 'Fwd Packet Length Mean',
            'Fwd Packet Length Std', 'Bwd Packet Length Max',
            'Bwd Packet Length Min', 'Bwd Packet Length Mean',
            'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s',
            'Flow IAT Mean', 'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min',
            'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
            'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std',
            'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
            'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
            'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
            'Min Packet Length', 'Max Packet Length', 'Packet Length Mean',
            'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
            'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
            'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
            'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
            'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
            'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
            'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward',
            'Active Mean', 'Active Std', 'Active Max', 'Active Min', 'Idle Mean',
            'Idle Std', 'Idle Max', 'Idle Min']
                        
        # Log the feature data and convert to pandas DataFrame
        logging.info([data])
        df = pd.DataFrame([data], columns=cols)

        # Convert DataFrame to numpy array for prediction
        df = np.array(df)
        
        # Make a prediction using the model
        predictions = self.model['classifier'].predict(df, output_margin=True)
        predicted_labels = self.model['classifier'].classes_[np.argmax(predictions, axis=1)]
        
        # Decode the predicted labels
        preds = self.label_encoder.inverse_transform(predicted_labels.astype(int))

        
        # store the prediction
        self.result = preds[0]
        y = self.result
        f = open('AIDS\\data\\predict.txt','a', encoding='utf-8')    

        # Alert if the prediction is not benign
        if y != 'BENIGN':
            print("Prediction:", RED, preds[0], ENDC)
            rules = "Alert "+str(self.flow.flowFeatures.getProtocol()).lower()+" "+str(self.flow.flowFeatures.getSrc())+" "+str(self.flow.flowFeatures.getSrcPort())+" -> "+str(self.flow.flowFeatures.getDest())+" "+str(self.flow.flowFeatures.getDestPort())+" (msg: \"Possible "+str(y)+";)"
            f.writelines(rules)
            print(RED, rules.encode('utf-8'), ENDC)
            logging.warning(rules.encode('utf-8'))

        # If benign, just log & print the result
        else:
            print("Prediction:", GREEN, preds[0], ENDC)
            msg = str(self.flow.flowFeatures.getProtocol()).lower()+" "+str(self.flow.flowFeatures.getSrc())+" "+str(self.flow.flowFeatures.getSrcPort())+" -> "+str(self.flow.flowFeatures.getDest())+" "+str(self.flow.flowFeatures.getDestPort())+" (msg: \""+str(y)+";)\n"
            print(GREEN, msg)
            logging.info(str(y))

        # Write the packet flow data and prediction to the CSV file
        with open(self.csv_file, mode='a', newline='', encoding='utf-8') as file:
            writer = csv.writer(file)
            try:
                writer.writerow([self.packet.tcp_flags,self.flow.flowFeatures.getFlowDuration(),self.flow.flowFeatures.getProtocol(),self.flow.flowFeatures.getSrc(), self.flow.flowFeatures.getSrcPort(), self.flow.flowFeatures.getDest(), self.flow.flowFeatures.getDestPort(), self.result])  # Write data row
            except:
                writer.writerow(["None",self.flow.flowFeatures.getFlowDuration(),self.flow.flowFeatures.getProtocol(),self.flow.flowFeatures.getSrc(), self.flow.flowFeatures.getSrcPort(), self.flow.flowFeatures.getDest(), self.flow.flowFeatures.getDestPort(), self.result])  # Write data row
               
    def newPacket(self, p):
        # Check if the packet is part of an existing flow
        if not Sniff(self.rulelist).inPacket(p):
            try:
                # Create a new packetDetails object to hold packet information
                packet = packetDetails()
                self.packet = packet

                # set packet details
                packet.setDest(p)
                # print("Destination: ",packet.getDest())
                packet.setSrc(p)
                # print("Source: ",packet.getSrc())
                packet.setSrcPort(p)
                packet.setDestPort(p)
                packet.setProtocol(p)
                packet.setTimestamp(p)
                packet.setFlag(p)
                packet.setPayloadBytes(p)
                packet.setHeaderBytes(p)
                packet.setPacketSize(p)
                packet.setWinBytes(p)
                packet.setID(p)

                # If the packet is part of an existing flow (forward direction)
                if packet.getFwdID() in self.current_flows.keys():
                    self.flow = self.current_flows[packet.getFwdID()]
                    # check for timeout (no new packet received in a long time)
                    if (packet.getTimestamp() - self.flow.getFlowLastSeen()) > self.FlowTimeout:
                        self.predict(self.flow.terminated())
                        del self.current_flows[packet.getFwdID()]
                        self.flow = Flow(packet)
                        self.current_flows[packet.getFwdID()] = self.flow

                    # check for fin or rst flag
                    elif packet.getFINFlag() or packet.getRSTFlag():
                        self.flow.new(packet, 'fwd')
                        self.predict(self.flow.terminated())
                        del self.current_flows[packet.getFwdID()]
                        del self.flow
                    else:
                        self.flow.new(packet, 'fwd')
                        self.current_flows[packet.getFwdID()] = self.flow
                        self.predict(self.flow.terminated())

                # If the packet is part of an existing flow (backwards)
                elif packet.getBwdID() in self.current_flows.keys():
                    self.flow = self.current_flows[packet.getBwdID()]

                    # check for timeout (no new packet received in a long time)
                    if (packet.getTimestamp() - self.flow.getFlowLastSeen()) > self.FlowTimeout:
                        self.predict(self.flow.terminated()) 
                        del self.current_flows[packet.getBwdID()]
                        del self.flow
                        self.flow = Flow(packet)
                        self.current_flows[packet.getFwdID()] = self.flow

                    # check for fin or rst flag
                    elif packet.getFINFlag() or packet.getRSTFlag():
                        self.flow.new(packet, 'bwd')
                        self.predict(self.flow.terminated())
                        del self.current_flows[packet.getBwdID()]
                        del self.flow
                    else:
                        self.flow.new(packet, 'bwd')
                        self.current_flows[packet.getBwdID()] = self.flow
                        self.predict(self.flow.terminated())

                #for first flow
                else:
                    self.flow = Flow(packet)
                    self.current_flows[packet.getFwdID()] = self.flow

            except AttributeError:
                print(RED, "Something Went Wrong with your Attribute", ENDC)
                return None

            except:
                traceback.print_exc()

    def run(self):
        print ("\nSniffing started....\n\nPress 'Esc' to quit the program\n\n----------------------------------------------------------------------------------------------------------------------\n\n")
        sniff(prn=self.newPacket, filter="", store=0, stop_filter=self.stopfilter)