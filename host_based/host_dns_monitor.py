from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR

# suspicious urls
suspicious_urls = ['www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com']

interface = 'eth0'
filter_bpf = 'udp and port 53'

def dns_monitor(pkts):
    for p in pkts:
        if p.haslayer(DNS):   
            if p.qdcount > 0 and isinstance(p.qd, DNSQR):
                name = p.qd.qname
            elif p.ancount > 0 and isinstance(p.an, DNSRR):
                name = p.an.rdata
            else:
                continue

            url = name.decode()[:-1]
            if url in suspicious_urls:
                os.system("wmic path win32_networkadapter where PhysicalAdapter=True call disable")
                os.system("netsh interface set interface Wi-Fi disable")

sniff(iface=conf.iface, filter=filter_bpf, store=0,  prn=dns_monitor)
