# MORIS LOCAL NETWORK SCANNER
## Video Demo:  <URL HERE>
## Description
### Introduction
The Class LocalNetworkScanner has serveral methods to utilise the [Scapy](https://pypi.org/project/scapy-python3/) Library to scan the local Network and find connected Devices and open Ports. 

We create a Network Package with an ARP and Ether Layer. With the help from the srp function, from the Scapy Lib, we sending that Package to ALL avaiable devices on the network using the broadcast adress. 

The srp() function returns a lot of Information, but we only need the IP Adress and MAC Address which we save in a dict.
The get_host_name() method uses the IP Adress to get the Device name.

The class can also scan the network using the ping_sweep() method, wich uses the subprocess lib to utilise windows commands.
Because we have to ping every ip seperate with windows commands, we use ThreadPoolExecutor to utilise Threads to speed the scan up. 

The port_scan() method uses the Scapy Lib to create a network packet with an IP and TCP Layer. With the help of the sr1 function we sending that packet to around 1000 port possibilites and filtere between open, closed or filtered. After that we save the ports in a dict and only post open ports.

We use logging to log errors, mostly for learning purpose.
We use Figlet to format our output in a cool way :stuck_out_tongue_winking_eye:
We validate IP Adresses with the ipadress lib.
To be able to use command parameters with use the argparse lib.


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
scan - The scan argument starts a scan using the [Scapy](https://pypi.org/project/scapy-python3/) Library.

old  - The old argument starts a scan using the windows terminal.

port - The port argument starts a port scan using the [Scapy](https://pypi.org/project/scapy-python3/) Library.

### Acknowledgments
-cs50p 

-google

-ChatGPT

-Kurt 


### Future Improvements
- [ ] adding more pytests
- [ ] better error handling for get_host_name()
- [ ] stop logging bullshit
- [ ] supporting linux for os terminal scans (--old)

