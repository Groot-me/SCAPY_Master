import Scapy_Ping,Scapy_DHCP,Scapy_HTTP,Scapy_Port_Scan,Scapy_OSI2,Scapy_XMAS,Scapy_WIFI_Scan,Scapy_Fake_Beacon,Scapy_SNMP
from Scapy_ARP import arp_spoofing



def main():
    #Scapy_Ping.PING("255.255.255.0")
    #Scapy_DHCP.DHCP_Server("eth0","192.168.201.2","2.2.2.2","8.8.8.8",500,2600)
    Scapy_HTTP.Http_Server()
    #arp_spoofing("192.168.2.1","192.16.2.1")
    #Scapy_OSI2.OSI2_Scan("192.168.201.0/24")
    #Scapy_Port_Scan.Port_Scanner("192.168.201.0/24",1024)
    #Scapy_XMAS.XMAS_Scanner("192.168.201.0/24",1024)
    #Scapy_WIFI_Scan.main()
    #Scapy_Fake_Beacon.Start_Fake_Beacon("Freewifi")
    #Scapy_SNMP.SNMP_Request("192.168.201.244","public","1.3.6.1.4.1.9.2.1.3.0")

if __name__ == '__main__':
    main()







