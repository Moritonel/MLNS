from project import LocalNetworkScanner, log_file_creater
import pytest
import logging
from scapy.layers.l2 import Ether, ARP


def test__str__():
    scanner = LocalNetworkScanner()
    assert str(scanner) == "You can scan your local Network with me! Try using the --help argument for more Info."

def test__init__():
    scanner = LocalNetworkScanner()
    assert scanner._scan == {}
    assert scanner._list_of_devices == []
    assert scanner._dict_of_ports == {}
    #tests to assert my dicts and lists in __init__ are initialized as empty

    assert isinstance(scanner._scapy_arp, ARP)
    assert isinstance(scanner._scapy_ether, Ether)
    #tests to assert Scapy ARP and Ether objects are initialized

def test_ip_check():
    with pytest.raises(RuntimeError, match=r"Invalid IP Address issued: .*"):
        LocalNetworkScanner(target_ip="invalid_ip_adress")

def test_log_file_creater():
    log_file_creater()
    logger = logging.getLogger(__name__)
    assert logger.name == __name__

