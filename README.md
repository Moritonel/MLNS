# MORIS LOCAL NETWORK SCANNER
## Video Demo:  <URL HERE>
## Description:
### Introduction
This project uses the [Scapy](https://pypi.org/project/scapy-python3/) Library to scan the local Network and find connected Devices. 
 


### Dependencies
Python libs: argparse, logging, socket, subprocess, ipaddress, sys, concurrent.futures
3rd party libs: scapy, pyfiglet

### Installation
install pcap
Link: https://npcap.com/#download
pip install -r requirements.txt

### Usage 
```
python project.py --scan 192.168.178.1
+-+-+-+-+ +-+-+-+-+-+-+-+
|S|C|A|N| |S|T|A|R|T|E|D|
+-+-+-+-+ +-+-+-+-+-+-+-+
This takes a few seconds...
IP Adress: 192.168.178.1   MAC Adress: 00:00:00:00:00:00 Device Name: fritz.box
IP Adress: 192.168.178.20  MAC Adress: 00:00:00:00:00:00 Device Name: DESKTOP-TPT7DKC.fritz.box
```







### Scanning Techniques
scan - using scapy lib
port - using scapy to search for open ports
old - using windows command


### Output Format
terminal only


### Error handling
using logging lib to document errors and saving them in an error.log


### Licenses
no clue for now^^


### Acknowledgments
-cs50p 
-google
-ChatGPT


### Future Improvements
-supporting more operating system for os terminal scans
