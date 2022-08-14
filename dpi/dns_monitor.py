# ./pox.py misc.full_payload forwarding.l2_learning dns_monitor samples.pretty_log log.level --DEBUG info.packet_dump

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from datetime import datetime

def DNSMON(event):
    # suspicious urls
    suspicious_urls = ["www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"]

    # parse the packet
    udp_packet = event.parsed.find('udp')

    if udp_packet is None:
        return
    # inspect destination port for ports 139 or 445
    elif udp_packet.dstport == 53:
        packet = event.parsed.find('dns')
        
        ip_request = event.parsed.find('ipv4')
   
        if packet is not None and packet.parsed:
            # check query name in 
            for query in packet.questions:
                if query.name in suspicious_urls:
                    detection_time = str(datetime.now())
                    print("suspicious url found ! <-> wannacry url accessed. At time:", detection_time)
                    
                    msg = of.ofp_flow_mod()
                    msg.match = of.ofp_match()
                    msg.idle_timeout = 1800
                    msg.hard_timeout = 1800
                    
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