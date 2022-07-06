from scapy.base_classes import Net
from scapy.all import DHCP_am

def DHCP_Server(Iface,Ip_Network,Ip_Mask,Gateway,Renew,release):

    #Transform subnet_mask to cidr
    CIDR = netmask_to_cidr(Ip_Mask)
    Ip_Network = Ip_Network + "/"+ str(CIDR)

    try:
        dhcp_start = DHCP_am(iface=Iface,
                         pool=Net(Ip_Network),
                         network=Ip_Network,
                         gw=Gateway,
                         renewal_time=Renew, lease_time=release)
        print("Server Starting !")
        dhcp_start()

    except Exception as e:
        print("Server failed !")
        print("Erreur :", e)


def netmask_to_cidr(netmask):
    return sum([bin(int(x)).count('1') for x in netmask.split('.')])



