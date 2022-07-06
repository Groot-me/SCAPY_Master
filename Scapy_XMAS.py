from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sr1
from COLOR import *
import Scapy_OSI2


class XMAS_Scanner:

    def __init__(self,Network, Port_range):

        self.Network = Network
        self.IP_LIST = []
        #Temp var because i don't need the MAC address for this scan
        MAC_LIST = []
        self.IP_LIST, MAC_LIST = Scapy_OSI2.OSI2_Scan(Network)
        self.IP_LIST.remove("192.168.201.1")
        self.XMAS_SCAN()

    def XMAS_SCAN(self):

        print("\nDébut du Scan XMAS :")

        for host in self.IP_LIST:
            print(f"Scan de {host} en cours ! ")
            for dst_port in range(10, 100):
                resp = sr1(IP(dst=host) / TCP(dport=dst_port, flags="FPU"), timeout=1, verbose=0)

                if (str(type(resp)) == "<class 'NoneType'>"):
                    print(f"{BBlue}{host}{Reset}:{BRed}{dst_port}{Reset} is possibly open. ")










