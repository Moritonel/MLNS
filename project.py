import argparse
import logging
import socket
import subprocess
import ipaddress
import sys
from pyfiglet import Figlet
from scapy.all import ARP, Ether, IP, TCP, srp, sr1
from concurrent.futures import ThreadPoolExecutor



class LocalNetworkScanner:
    def __init__(self, target_ip="192.168.178.1"):
        #default ip is my network ip 
        if ip_check(target_ip) == True:
            self._target_ip: str = target_ip
            self._target_ip_with_mask: str = self._format_ip(self._target_ip)
            # Subnet mask in CDIR format, only /24 to keep the tool simple
            self._dst: str = "ff:ff:ff:ff:ff:ff"
            # broadcast address. sent to all devices on the network. 
            self._scapy_arp = ARP(pdst=self._target_ip_with_mask)
            # using Scapy to create an ARP Layer
            self._scapy_ether = Ether(dst=self._dst)
            # using Scapy to create an Ether Layer
            self._packet1 = self._scapy_ether / self._scapy_arp
            # creates a network packet, with ARP and Ether layers using scapy
            self._scan: dict = {}
            # dict of ip and mac adress 
            self._list_of_devices: list = []
            # list of device ips, found by ping sweep
            self._dict_of_ports: dict = {}
            # dict of all ports found by port scan
        else:
            raise RuntimeError(f"Invalid IP Address issued: {target_ip}")
         
         
    def __str__(self):
        return "You can scan your local Network with me! Try using the --help argument for more Info."
    # type: -> Str


    def scan(self):
        # scan() uses the srp function from scapy to send a network packet
        # we return the IP and Mac from answering devices as a 
        try:
            result = srp(self._packet1, timeout=3, verbose=0)[0]
            for _, received in result:
                self._scan[received.psrc] = received.hwsrc 
                #IP Adress = received.psrc / MAC Address = received.hwsrc
            return self._scan
        
        except PermissionError as pe:
            logging.getLogger(__name__).exception(f"Exception: {pe} type: {type(pe)}")
            exit("Permission Error! See error.log for more info. Tool is exiting")          
    # type: -> Dict

    
    def get_host_name(self, ip: str):
        # getting host name with socket() method using the provided IP Adress
        try:
            self._host_info = socket.gethostbyaddr(ip)
            self._host_name = self._host_info[0]
            return self._host_name
        
        except socket.error as se:
           logging.getLogger(__name__).exception(f"Exception: {se} type: {type(se)}")
           return "Hostname not found"          
    # type: -> Str


    def ping_sweep(self):
        with ThreadPoolExecutor(max_workers=50) as executor:
        #using threads to speed up scan                  
            for i in range(1, 255):
                ip_adress: str = f"{self._target_ip_with_mask[:-5]}.{i}"
                command: list = ["ping", "-n", "1", "-w", "500", ip_adress]
                executor.submit(self._ping_worker, command, ip_adress)
            return self._list_of_devices
    # type: -> List


    def _ping_worker(self, command: list, ip_adress: str):
        # function to ping an IP range and get active devices using subprocess lib (windows only)
        try:                      
            subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            # using windows ping command suppressing errors and output
            self._list_of_devices.append(ip_adress)
            # adds ip adress if there is no error
        except subprocess.CalledProcessError as pe: 
            logging.getLogger(__name__).exception(f"Exception: {pe} type: {type(pe)}")
            # if there is an error it doesnt add the ip (not getting an answer counts as error)
            pass
            



    def port_scan(self, min_port=1, max_port=1025):
        with ThreadPoolExecutor(max_workers=50) as executor:
            # using threads to speed up scan (otherwise takes minutes)
            for port in range(min_port, max_port):
                executor.submit(self._port_worker, port)
        return self._dict_of_ports
    # type: -> Dict
    

    def _port_worker(self, port: int):
            scapy_ip = IP(dst=self._target_ip)
            # using Scapy to create an IP Layer
            scapy_tcp = TCP(dport=port, flags="S")
            # using Scapy to create an TCP Layer / flags is set for SYN (Synchronize)
            packet = scapy_ip / scapy_tcp
            # creates a network packet, with IP and TCP layers using scapy
            response = sr1(packet, timeout=1, verbose=0)
            #sends a network packet and waits for response
            if response is not None and response.haslayer(TCP):
            # if scapies object exits and has a TCP layer
                if response[TCP].flags == 0x12:
                # 0x12 represents in hexadecimal the combination of flags in TCP 
                # that correspond to a SYN/ACK respons, indicating the port is open
                    self._dict_of_ports.update({port: "open"})
                else:
                    self._dict_of_ports.update({port: "closed"})
            else:
                self._dict_of_ports.update({port: "filtered or closed"}) 
            # response is none and has no TCP layer means 
            # no answer at all, filtered or maybe unknown Errors 


    def _format_ip(self, ip: str):
    # ouput: network address / subnet mask in CIDR 
    # we split the ip on the dot, remove the host adress if needed and adding the subnet mask
        splits = ip.split(".")
        if len(splits) >= 2:
             removed_end_ip = splits[:-1]
             formatted_ip = ".".join(removed_end_ip) + ".0/24"
             return formatted_ip
        else:
            print("Invalid IP Adress")
    # type: -> Str

def log_file_creater():
    # looging is used rarly and mainly for learning purpose
    # this function creates a logger obj and formats the output 
    logger = logging.getLogger(__name__)
    file_handler = logging.FileHandler("errors.log")
    file_handler.setLevel(logging.ERROR)
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)



def ip_check(ip):
    # using ipadress lib to validate ip address and logs if there is an Value error
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError as ve:
        logging.getLogger(__name__).exception(f'invalid ip issued: {ip} ! Error: {ve}')
        return False
# type: -> Bool

def get_args():
    #checking for args in command version
    parser = argparse.ArgumentParser(description="Moris Local Network Scanner")
    parser.add_argument("--scan", dest="scan", help="Target IP Range - Example: 192.168.178.0/24")
    parser.add_argument("--old", dest="old", help="Target IP Range - Example: 192.168.178.0/24 using windows commands")
    parser.add_argument("--port", dest="port", help="Target IP for Port Scan - Example: 192.168.178.20")
    parser.add_argument("--mask", dest="mask", help="runs all functions like the main args, but doesn't print any real data")
    return parser.parse_args()
# type: -> Namespace

def main():
    log_file_creater()
    # creating Logging Obj
    args = get_args()
    # getting all submitted args
    if args.scan:
        #scapy scan and using figlet for formatting output
        scanner = LocalNetworkScanner(target_ip=args.scan)
        figlet = Figlet(font="digital")
        print(figlet.renderText("SCAN STARTED"), end="")
        print("This takes a few seconds...", flush=True)
        # flush=True is needed to print directly, else python is waiting for the scan and prints both 
        results = scanner.scan()
        for ip, mac in results.items():
            if ip_check(ip) == True:
                print(f"IP Adress: {ip: <15} MAC Adress: {mac} Device Name: {scanner.get_host_name(ip)}")
            else:
                print(f"Invalid IP: {ip}")
                      

    elif args.old:
        # windows commands scan (slow af) and figlet for formatting
        scanner = LocalNetworkScanner(target_ip=args.old)
        figlet = Figlet(font="digital")
        print(figlet.renderText("SCAN STARTED"), end="")
        print("This takes a few seconds...", flush=True)
        # flush=True is needed to print directly, else python is waiting for the scan and prints both 
        with ThreadPoolExecutor(max_workers=50) as executor:
            finished = executor.submit(scanner.ping_sweep)
            devices: list = finished.result()

        print(figlet.renderText(f"FOUND DEVICES"), end="")
        for ip in devices:
            print(f"IP Adress: {ip: <15}")

    elif args.port:
        # port scan using scapy
        print("This takes a few seconds...")
        scanner = LocalNetworkScanner(target_ip=args.port)
        scanner.port_scan()
        sorted_ports: dict = dict(sorted(scanner._dict_of_ports.items(), key=lambda x: x[0]))
        # dict contains open, closed and filtered or closed ports using the port as sorting key
        for port, status in sorted_ports.items():
            if status == "open":
                print(f"Port: {port} is {status}")
            elif status == "filtered or closed":
                print(f"Port: {port} is {status}")

    elif args.mask:
        ...
    


    else:
        # if no args are given asking for user input and using the same scans like the args version
        # maybe i can combine them without introducing new bugs?^^
        while True:
            user_ip: str = input("IP of Host Device: ")
            if ip_check(user_ip) == True:
                print("valid")
                while True:
                    user_choice = input("Choose between scan, old, port or end: ")
                    if user_choice.lower() == "scan":
                        #scapy scan and using figlet for formatting output
                        scanner = LocalNetworkScanner(user_ip)
                        figlet = Figlet(font="digital")
                        print(figlet.renderText("SCAN STARTED"), end="")
                        print("This takes a few seconds...", flush=True)
                        # flush=True is needed to print directly, else python is waiting for the scan and prints both 
                        results = scanner.scan()
                        for ip, mac in results.items():
                            if ip_check(ip) == True:
                                print(f"IP Adress: {ip: <15} MAC Adress: {mac} Device Name: {scanner.get_host_name(ip)}")
                            else:
                                print(f"Invalid IP: {ip}")
                    
                    elif user_choice.lower() == "old":
                            # windows commands scan (slow af) and figlet for formatting
                            scanner = LocalNetworkScanner(user_ip)
                            figlet = Figlet(font="digital")
                            print(figlet.renderText("SCAN STARTED"), end="")
                            print("This takes a few seconds...", flush=True)
                            # flush=True is needed to print directly, else python is waiting for the scan and prints both 
                            with ThreadPoolExecutor(max_workers=50) as executor:
                                finished = executor.submit(scanner.ping_sweep)
                                devices: list = finished.result()

                            print(figlet.renderText(f"FOUND DEVICES"), end="")
                            for ip in devices:
                                print(f"IP Adress: {ip: <15}")

                    elif user_choice.lower() == "port":
                        # port scan using scapy
                        print("This takes a few seconds...")
                        scanner = LocalNetworkScanner(user_ip)
                        scanner.port_scan()
                        sorted_ports: dict = dict(sorted(scanner._dict_of_ports.items(), key=lambda x: x[0]))
                        # dict contains open, closed and filtered or closed ports using the port as sorting key
                        for port, status in sorted_ports.items():
                            if status == "open":
                                print(f"Port: {port} is {status}")

                    elif user_choice.lower() == "end":
                        sys.exit("Thanks for testing!")


            else:
                print("invalid")
                # given user ip is invalid
        

if __name__ == "__main__":
    main()


