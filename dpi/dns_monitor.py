# ./pox.py misc.full_payload forwarding.l2_learning dns_monitor samples.pretty_log log.level --DEBUG info.packet_dump

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from datetime import datetime
import csv

# read suspicious urls from a csv file
suspicious_urls = []
with open('malicious_urls.csv', 'r') as read_obj:
    csv_reader = csv.reader(read_obj)
    list_of_rows = list(csv_reader)
    for rows in list_of_rows:
        suspicious_urls.append(rows[0])

def DNSMON(event):
    # search for UDP packets
    udp_packet = event.parsed.find('udp')

    # if packet is not UDP return it to forwarding.l2_learning component
    if udp_packet is None:
        return
    # inspect destination port for 53
    elif udp_packet.dstport == 53:
        # search for DNS specific packets
        packet = event.parsed.find('dns')
        
        ip_request = event.parsed.find('ipv4')

        # check if the packet is DNS specific
        if packet is not None and packet.parsed:
            # check query name in dns packet questions
            for query in packet.questions:
                if query.name in suspicious_urls:
                    detection_time = str(datetime.now())
                    print("suspicious url found ! <-> wannacry url accessed. At time: ", detection_time)
                    
                    # modify flow table entries to add the following matching entries
                    msg = of.ofp_flow_mod()
                    msg.match = of.ofp_match()
                    msg.idle_timeout = 1800
                    msg.hard_timeout = 1800
                    
                    # install a rule to block the host
                    for connection in core.openflow.connections:
                        connection.send(msg)
                        core.getLogger("DNS Requests Monitor").debug("blocked host with IP %s for 30 minutes from communicating in the network", ip_request.srcip)
                        event.halt = True
                return
            else:
                return
    else:
        return

def launch():
    core.openflow.addListenerByName("PacketIn", DNSMON, priority = 10000)
