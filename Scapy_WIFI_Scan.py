import sys

from scapy.layers.dot11 import Dot11Beacon, Dot11, Dot11Elt
from scapy.sendrecv import sniff
from threading import Thread,Event
import time,os,subprocess
from COLOR import *


WIFI_output = []
STOP = False

def callback(packet):
    if packet.haslayer(Dot11Beacon):
        # extract the MAC address of the network
        bssid = packet[Dot11].addr2
        # get the name of it
        ssid = packet[Dot11Elt].info.decode()

        # extract network stats
        stats = packet[Dot11Beacon].network_stats()

        #Get channel
        channel = stats.get("channel")
        # get the crypto
        crypto = stats.get("crypto")

        found = False
        for wifi in WIFI_output:
            if(wifi == f"Wifi Found MAC:{BGreen}{bssid}{Reset}  Name:{BPurple}{ssid}{Reset}  Crypto:{BYellow}{crypto}{Reset} Channel:{BCyan}{channel}{Reset}"):
                found = True

        if(not found):
            WIFI_output.append(f"Wifi Found MAC:{BGreen}{bssid}{Reset}  Name:{BPurple}{ssid}{Reset}  Crypto:{BYellow}{crypto}{Reset} Channel:{BCyan}{channel}{Reset}")


#there is 14 channel on wifi 2.4GHZ : https://en.wikipedia.org/wiki/List_of_WLAN_channels
#and more on 5Ghz so let's get them all and scan
def change_channel():
    stdout = subprocess.Popen("iwlist wlan0mon channel | grep -oP '(?<=Channel ).*?(?=: )'", shell=True, stdout=subprocess.PIPE).stdout
    output = stdout.read().decode().removesuffix("\n").replace(" \n",",").split(",")
    for channel in output:
        os.system(f"iwconfig wlan0mon channel {channel}")
        time.sleep(0.3)

    #once finish we call the print fonction and we close the thread
    print_all()
    global STOP
    STOP = True

def print_all():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("Scan finished :")
    for wifi in WIFI_output:
        print(wifi)

    return 0

def main():
    # interface name, check using iwconfig
    interface = "wlan0mon"

    # start the channel changer
    channel_changer = Thread(target=change_channel)
    channel_changer.daemon = True
    channel_changer.start()

    # start sniffing
    try:

        #Create Thread for stop the sniffing
        e = Event()
        def _sniff(e):
            sniff(prn=callback, iface=interface,stop_filter=lambda p: e.is_set())

        print("Scanning starting !")
        t = Thread(target=_sniff, args=(e,))
        t.start()

        while(STOP == False):
            pass
        e.set()
    except Exception as e:
        print("Une erreur est survenue... ")
        print("Vérifiez si votre carte wifi est en mode monitoring")
        print("Erreur : ",e)

if __name__ == "__main__":
    main()