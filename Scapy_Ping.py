from scapy import *
from scapy.layers.inet import ICMP
from scapy.sendrecv import sr
from scapy.layers.inet import IP


def PING(Ip_Address):

    if(Is_Valid(Ip_Address)):
        ans, unans = sr(IP(dst=Ip_Address) / ICMP()/str("https://github.com/Groot-me"), timeout=3)

        if(ans == None):
            print("Ping failed !!")
        else:
            print("Ping successful !!")
    else:
        print("Wrong IP !!!")

#Test de validité de mon addresse ipv4
def Is_Valid(Ip_Valid):
    ip = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$",Ip_Valid)
    if ((ip) == None):
        return 0
    else:
        return 1