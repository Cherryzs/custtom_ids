from scapy.all import *
import time

for i in range(1,10):   # boleh pilih mana-mana range dalam 192.168.56.0/24
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(op=1, pdst=f"192.168.56.{i}")
    sendp(pkt, iface="eth1")   # eth1 = interface Kali host-only
    time.sleep(2)
