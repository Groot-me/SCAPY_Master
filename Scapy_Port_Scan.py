from scapy.all import *
from COLOR import *
import Scapy_OSI2


class Port_Scanner:

    def __init__(self,Network, Port_range):

        self.Network = Network
        self.IP_LIST = []
        #Temp var because i don't need the MAC address for this scan
        MAC_LIST = []
        self.IP_LIST, MAC_LIST = Scapy_OSI2.OSI2_Scan(Network)
        self.PORT_SCAN()

    def PORT_SCAN(self):

        print("\nDébut Scan de port :")
        for host in self.IP_LIST:
            print(f"Scan de {host} en cours ! ")
            for dst_port in range(10,100):
                resp = sr1(IP(dst=host) / TCP(dport=dst_port, flags="S"), timeout=1, verbose=0)

                if resp is None:
                    pass
                elif(resp.getlayer(TCP).flags == 0x12):
                    print(f"{BBlue}{host}{Reset}:{BRed}{dst_port}{Reset} is open.")

