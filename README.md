#  A Hybrid Network Intrusion Detection System Using XGBoost
# Overview
This project is a **Network Intrusion Detection System (NIDS)** that combines Signature-based Intrusion Detection (SIDS) and Anomaly-based Intrusion Detection (AIDS) techniques to identify and mitigate potential cyber threats. The system is implemented in Python, leveraging libraries like Scapy for packet sniffing, XGBoost for anomaly detection, and additional utilities for data manipulation and rule-based filtering. It uses a rule file to identify known malicious patterns and machine learning models to detect deviations from normal network behavior. The project includes tools such as `keyboard` for real-time control, logging for activity tracking, and argparse for dynamic file input. It provides an interactive framework to analyze live network traffic, log suspicious activities, and stop monitoring upon user command, ensuring efficient and dynamic protection against both known and unknown threats.
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
1. Install Python version 3.8 or later.

2. Install the required python packages:

```
$ pip install -r requirements.txt
```

## Usage
To use the Hybrid IDS run the following command, replacing the file path for the rules.txt file:

```
$ python3 IDS.py -f "C:\Users\LENOVO\OneDrive\Documents\U\4\CNS Project 2\Intrusion-Detection-System-main\Intrusion-Detection-System-main\IDS_Final\SIDS\rules.txt"
```

## Contributing 
Advice and contributions are welcome! Please submit a pull request if you have any suggestions, improvements, or bug fixes.

## Authors 
Mark Njore

## Acknowledgments
I would like to express my sincere gratitude to everyone who has contributed to the success of this project.
