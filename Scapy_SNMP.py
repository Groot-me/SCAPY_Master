from scapy.asn1.asn1 import ASN1_OID
from scapy.layers.inet import IP,UDP
from scapy.layers.snmp import SNMP, SNMPvarbind, SNMPget
from scapy.sendrecv import sr1
from COLOR import *

def SNMP_Request(Dst_IP,Community,OID):
   snmp = IP(dst=Dst_IP)/UDP(dport=161)/SNMP(community=Community, PDU=SNMPget(varbindlist=[SNMPvarbind(oid=ASN1_OID(OID))]))
   resp = sr1(snmp,verbose=0)

   print(f"Reponse obtenue avec l'oid suivant : {BBlue}{OID}{Reset} -> {BPurple}{resp[SNMP][2].value.val.decode()}{Reset}" )


