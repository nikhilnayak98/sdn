# pyinstaller --onefile host_dns_monitor.py

from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
import csv

# read suspicious DNS requests from a csv
suspicious_urls = []
with open('suspicious_dns_requests.csv', 'r') as read_obj:
    csv_reader = csv.reader(read_obj)
    list_of_rows = list(csv_reader)
    for rows in list_of_rows:
        suspicious_urls.append(rows[0])

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

            # extract URL
            url = name.decode()[:-1]
            # check if URL is in suspicious list
            if url in suspicious_urls:
                print("WannaCry URL Found: " + str(url))
                print("Disabling Network Adapters")
                
                # disable physical network adapter
                os.system("wmic path win32_networkadapter where PhysicalAdapter=True call disable")
                # disable Wifi
                os.system("netsh interface set interface Wi-Fi disable")

sniff(iface=conf.iface, filter=filter_bpf, store=0,  prn=dns_monitor)
