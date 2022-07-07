import Scapy_Ping,Scapy_DHCP,Scapy_HTTP,Scapy_Port_Scan,Scapy_OSI2,Scapy_XMAS,Scapy_WIFI_Scan,Scapy_Fake_Beacon,Scapy_SNMP
from Scapy_ARP import arp_spoofing
from COLOR import *
import os

def main():

    while True:
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"""{BGreen}  
███████  ██████  █████  ██████  ██    ██     ███    ███  █████  ███████ ████████ ███████ ██████  
██      ██      ██   ██ ██   ██  ██  ██      ████  ████ ██   ██ ██         ██    ██      ██   ██ 
███████ ██      ███████ ██████    ████       ██ ████ ██ ███████ ███████    ██    █████   ██████  
     ██ ██      ██   ██ ██         ██        ██  ██  ██ ██   ██      ██    ██    ██      ██   ██ 
███████  ██████ ██   ██ ██         ██        ██      ██ ██   ██ ███████    ██    ███████ ██   ██ 
{Reset}
       {BBlue}                                                                                       
       Welcome To scapy testing tools !!
       Choose what u want to do : {Reset}
       
       1) Simple Ping
       2) Rogue DHCP Server
       3) HTTP Server 
       4) Arp Spoofing 
       5) Port Scan
       6) XMAS Scan
       7) OSI2 Scan
       8) AP Scan
       9) Fake Beacon
       10) SNMP Request
        """)
        choice = input("       >>> ")

        answer = {0: 'here_for_size', 1:Scapy_Simple_Ping , 2: Scapy_Rogue_DHCP, 3: Scapy_HTTP_Server, 4 : Scapy_Arp_Spoofing, 5 : Scapy_Scan_port, 6 : Scapy_XMAS_Scan, 7: Scapy_OSI2_scan, 8 : Scapy_AP_sCAN,9:Fake_Beacon, 10: SNMP_Req}

        for x in range(1,len(answer)):
            if (choice == str(x)):
                answer[x]()

        break




def Scapy_Simple_Ping():
    ip = input("       IP to PING >> ")
    Scapy_Ping.PING(ip)

def Scapy_Rogue_DHCP():
    iface = input("       Listening interface >> ")
    ip_network = input("       Network (no CIDR) >> ")
    Subnet_mask = input("       Subnet Mask (no CIDR) >> ")
    Ip_Gateway = input("       Ip Gateway >> ")

    Renew = 0
    Release = 0
    try:
        Renew = input("       Renew Time >> ")
        Renew = int(Renew)
        Release = input("   Release Time >> ")
        Release = int(Release)

    except Exception as e:
        print("An error Occur", e)

    Scapy_DHCP.DHCP_Server(iface, ip_network , Subnet_mask, Ip_Gateway , Renew, Release)

def Scapy_HTTP_Server():
    Scapy_HTTP.Http_Server()

def Scapy_Arp_Spoofing():


    ip_victim = input("       IP of the victim >> ")
    ip_gateway = input("       IP of the gateway >> ")

    arp_spoofing(ip_victim,ip_gateway)


def Scapy_Scan_port():
    network = input("   Network ex : 10.10.10.10/24 >> ")
    range = input("       Port range ex : 10-100 or '1,22,80,443,3306 >> ")
    Scapy_Port_Scan.Port_Scanner(network,range)


def Scapy_XMAS_Scan():
    network = input("       Network ex : 10.10.10.10/24 >> ")
    range = input("       Port range ex : 10-100 or '1,22,80,443,3306 >> ")
    Scapy_XMAS.XMAS_Scanner(network,range)

def Scapy_OSI2_scan():

    network = input("       Network ex : 10.10.10.10/24 >> ")
    Scapy_OSI2.OSI2_Scan(network)

def Scapy_AP_sCAN():
    Scapy_WIFI_Scan.main()

def Fake_Beacon():
    Wifi_Name = input("       Nom du faux beacon >> ")
    Scapy_Fake_Beacon.Start_Fake_Beacon(Wifi_Name)


def SNMP_Req():
    Ip = input("       Ip host >> ")
    Community = input("       Community >> ")
    Oid = input("       OID >> ")
    Scapy_SNMP.SNMP_Request(Ip,Community,Oid)




if __name__ == '__main__':
    main()







