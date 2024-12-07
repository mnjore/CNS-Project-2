# DDoS attack Detection Model based on Entropy Computing
#Overview
This project aims to develop a Hybrid Network Intrusion Detection System (NIDS) by combining machine learning techniques to enhance the detection of network intrusions. The system leverages both traditional rule-based and machine learning-based approaches to provide a more robust mechanism for identifying malicious network activities.
## Technologies Used
- VirtualBox
- Kali
- Python
- VSCode
- Google Colab
- Jupyter Notebook
- hping
- arpspoof
- slowhttptest
## Installation
To install the IDS, follow these steps:
1. Install an OS that can install a Python version between 3.8 to 3.9:

* This can be found at https://releases.ubuntu.com/

2. Install various tools to be used:

```
$ sudo apt install vim
$ sudo apt install python3-pip
$ sudo apt install git
```

3. Install Mininet for network simulation:

```
$ sudo apt install mininet
```

4. Install XTerm terminal emulator:

```
$ sudo apt install xterm
```

4. Install Scapy for packet generation:

```
$ sudo apt-get install python3-scapy
```

5. Install the SDN controller (POX is used here):

```
$ pip install pox
$ git clone http://github.com/noxrepo/pox
```

## Usage
To use the DDoS attack detection model, follow these steps:

1. Create a Mininet topology by entering the following command:

```
$ sudo mn --switch ovsk --topo tree,depth=2,fanout=8 --controller=remote,ip=127.0.0.1,port=6633
```

2. Run the Pox controller in a separate terminal:

```
$ cd pox
$ python3 ./pox.py forwarding.l3_learning_edited
```

3. Run Xterm on a host and generate traffic:

```
$ xterm h1
$ python3 traffic.py –f 2 –l 64
```

Where f = first value and l = last value of the number of hosts we want to send packets. After the successful completion of the above steps, you can see the entropy values on the POX controller terminal.

4. Launch the DDoS attack on a specific host:

```
$ python3 ddos_attack.py 10.0.0.64
```

After the successful completion of the above steps, you can see that the DDoS attack has been detected on the POX controller terminal. 


## Contributing 
Advice and contributions are welcome! Please submit a pull request if you have any suggestions, improvements, or bug fixes.

## Authors 
Mark Njore

## Acknowledgments
I would like to start by expressing my sincere gratitude to everyone who has contributed to the success of this project. First of all, I would like to express my sincere gratitude to the supervisor, Dr. Rop, for his advice, support and knowledge throughout the project. The direction and amount of this work were greatly influenced by Mr. Tabulu, the project lecturer with his insightful comments and helpful critiques. He also provided me with important tools and supporting scientific material that helped in the research and documentation process. I would also like to express my sincere gratitude to my family and friends for their constant support and inspiration.  Finally, we would like to thank the open source community for providing the essential tools and software.
