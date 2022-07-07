from scapy.all import *
from COLOR import *
import Scapy_OSI2


class Port_Scanner:

    def __init__(self,Network, Port_range):


        self.Network = Network
        self.IP_LIST = []
        self.Port_Range = Port_range
        #Temp var because i don't need the MAC address for this scan
        MAC_LIST = []
        self.IP_LIST, MAC_LIST = Scapy_OSI2.OSI2_Scan(Network)
        self.PORT_SCAN()

    def PORT_SCAN(self):

        print("\nDébut Scan de port :")
        for host in self.IP_LIST:
            print(f"Scan de {host} en cours ! ")
            range_port = self.arrange_port()
            for dst_port in range_port:
                resp = sr1(IP(dst=host) / TCP(dport=dst_port, flags="S"), timeout=1, verbose=0)

                if resp is None:
                    pass
                elif(resp.getlayer(TCP).flags == 0x12):
                    print(f"{BBlue}{host}{Reset}:{BRed}{dst_port}{Reset} is open.")


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



