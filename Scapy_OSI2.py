from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp


def OSI2_Scan(Network):

    try:
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=Network), timeout=2, verbose=0)

        print("Scan Terminé !")
        print("Résultat :     IP:                 MAC:")
        IP_List = []
        MAC_List = []
        for response in ans:
            IP_List.append(response[1].psrc)
            MAC_List.append(response[1].hwsrc)
            print(f"                \033[1;34m{response[1].psrc}\033[0m          \033[1;32m{response[1].hwsrc}\033[0m")

        return IP_List, MAC_List
    except Exception as e:
        print("An error occur ", e)


