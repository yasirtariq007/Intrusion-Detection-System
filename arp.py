from scapy.utils import rdpcap
from scapy.layers.all import *

attacker = {}

def main():
    file = rdpcap('arpspoofing.pcap')

    for i, bman in enumerate(file):
        if (bman.haslayer(ARP)):
            getting(bman)
            found = identity(bman)
            printing(found, i+1)

def getting(num):
    if ((num.psrc and num.hwsrc) not in attacker): # pscr = SourceIPField   hwscr = ARPSourceMACField
        attacker[num.psrc] = num.hwsrc

def identity(bman):
    if bman.dst != '00:12:0B:D4:45:E6':
        if not((find_spoofip(bman.pdst) == bman.pdst and attacker.get(bman.dst) == bman.dst)):# pdst = IPField  scr = SourceMACField  dst = DestinationMACField
            return bman.src

def find_spoofip(attmac):
	for ipadd, macadd in attacker.items():
		if (macadd == attmac):
			return ipadd

def printing(num, pckt_number):
    if (num != None):
        print("Attackers MAC address: {}".format(num))
        print("Packet number: {}".format(pckt_number))
main()