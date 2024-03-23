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
**python project.py --help**
```
usage: project.py [-h] [--scan SCAN] [--old OLD] [--port PORT]

Moris Local Network Scanner

options:
  -h, --help   show this help message and exit
  --scan SCAN  Target IP Range - Example: 192.168.178.0/24
  --old OLD    Target IP Range - Example: 192.168.178.0/24 using windows commands
  --port PORT  Target IP for Port Scan - Example: 192.168.178.20
```
**python project.py --scan 192.168.178.1**
```
+-+-+-+-+ +-+-+-+-+-+-+-+
|S|C|A|N| |S|T|A|R|T|E|D|
+-+-+-+-+ +-+-+-+-+-+-+-+
This takes a few seconds...
IP Adress: 192.168.178.1   MAC Adress: 00:00:00:00:00:00 Device Name: fritz.box
IP Adress: 192.168.178.20  MAC Adress: 00:00:00:00:00:00 Device Name: DESKTOP-TPT7DKC.fritz.box
```
**python project.py --old 192.168.178.1**
```
+-+-+-+-+ +-+-+-+-+-+-+-+
|S|C|A|N| |S|T|A|R|T|E|D|
+-+-+-+-+ +-+-+-+-+-+-+-+
This takes a few seconds...
+-+-+-+-+-+ +-+-+-+-+-+-+-+
|F|O|U|N|D| |D|E|V|I|C|E|S|
+-+-+-+-+-+ +-+-+-+-+-+-+-+
IP Adress: 192.168.178.1  
IP Adress: 192.168.178.20 
IP Adress: 192.168.178.23 
```
**python project.py --port  192.168.178.1**
```
This takes a few seconds...
Port: 53 is open
Port: 80 is open 
Port: 443 is open
Port: 554 is open
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
