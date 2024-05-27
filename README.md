# MORIS LOCAL NETWORK SCANNER
## Video Demo:  [MLNS](https://youtu.be/rjNjBdBMGLg)
## Description
### Introduction
The Class LocalNetworkScanner has several methods to utilize the [Scapy](https://pypi.org/project/scapy-python3/) Library to scan the local network, find connected Devices and open Ports. 

We create a Network Package with an ARP and Ether Layer. With the help of the srp function, from the Scapy Lib, we're sending that Package to ALL available devices on the network using the broadcast address. 

The srp() function returns a lot of Information, but we only need the IP Address and MAC Address, which we save in a dictionary.
The get_host_name() method uses the IP Address to get the Device name.

The class can also scan the network using the ping_sweep() method, which uses the subprocess lib to utilize Windows commands.
Because we have to ping every IP separately with Windows commands, we use ThreadPoolExecutor to utilize Threads to speed up the scan. 

The port_scan() method uses the Scapy Lib to create a network packet with an IP and TCP Layer. With the help of the sr1 function, we're sending that packet to around 1000 port possibilities and filter between open, closed or filtered. After that, we save the ports in a dictionary and only post open ports.

We use logging to log errors, mostly for learning purposes.

We use Figlet to format our output in a cool way :stuck_out_tongue_winking_eye:

We validate IP Addresses with the ipaddress lib.

To be able to use command parameters, we use the argparse lib.

### Dependencies
Python libs: argparse, logging, socket, subprocess, ipaddress, sys, concurrent.futures

3rd party libs: scapy, pyfiglet

### Installation
install [Npcap](https://npcap.com/#download)

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

-google and other searchengines

-ChatGPT (only for Explanations)

-Kurt (best Dude ever)


### Future Improvements
- [ ] adding more pytests
- [ ] better error handling for get_host_name()
- [ ] stop logging bullshit
- [ ] supporting linux for os terminal scans (--old)

