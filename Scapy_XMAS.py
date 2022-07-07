from scapy.layers.inet import TCP, IP
from scapy.sendrecv import sr1
from COLOR import *
import Scapy_OSI2


class XMAS_Scanner:

    def __init__(self,Network, Port_range):

        self.Network = Network
        self.IP_LIST = []
        self.Port_Range = Port_range
        #Temp var because i don't need the MAC address for this scan
        MAC_LIST = []
        self.IP_LIST, MAC_LIST = Scapy_OSI2.OSI2_Scan(Network)
        self.IP_LIST.remove("192.168.201.1")
        self.XMAS_SCAN()

    def XMAS_SCAN(self):

        print("\nDébut du Scan XMAS :")

        for host in self.IP_LIST:
            print(f"Scan de {host} en cours ! ")
            range_port = self.arrange_port()
            for dst_port in range_port:
                resp = sr1(IP(dst=host) / TCP(dport=dst_port, flags="FPU"), timeout=1, verbose=0)

                if (str(type(resp)) == "<class 'NoneType'>"):
                    print(f"{BBlue}{host}{Reset}:{BRed}{dst_port}{Reset} is possibly open. ")


    def arrange_port(self):

        tab_array = []
        try:
            if("-" in self.Port_Range): #range
                tab = str(self.Port_Range).split('-')
                for i in range(int(tab[0]),int(tab[1])):
                    tab_array.append(i)

                return tab_array
            elif ("," in self.Port_Range): # comma separated port
                tab =  str(self.Port_Range).split(',')
                for string in tab:
                    tab_array.append(int(string))
                return tab_array
            else:#There is just one port
                tab_array.append(int(self.Port_Range))
                return tab_array
        except Exception as e:
            print("an error Occur ", e)






