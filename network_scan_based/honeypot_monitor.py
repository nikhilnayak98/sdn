# ./pox.py misc.full_payload forwarding.l2_learning honeypot_monitor samples.pretty_log log.level --DEBUG info.packet_dump

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
from datetime import datetime

def HTTP_handler():
    print("A HTTP request to the HoneyPot")

def SMB_handler():
    print("A SMB request to the HoneyPot")

def HPM(event):
    # define ports
    listening_ports = [80, 443, 139, 445]
    # define honeypot address in the network
    honeypot_address = "192.168.1.7"

    # search for TCP packets
    Received_packet = event.parsed.find('tcp')
    if Received_packet is None:
        return
    # check if destination port is 445, 80, 443
    elif Received_packet.dstport in listening_ports:
        IP = event.parsed.find('ipv4')
        ipaddr = IP.dstip

        # match the destination IP with the honeypot IP
        if ipaddr == honeypot_address:
            ip_packet = event.parsed.find('ipv4')
            ipaddr = IP.srcip
            
            detection_time = str(datetime.now())
            print("suspicious connection found ! <-> connection to honeypot from %s to %i. At time: %s", Received_packet.srcport, Received_packet.dstport, detection_time)
            
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x800
            msg.match.nw_src = ipaddr
            msg.match.nw_proto = 6
            msg.match.tp_dst = Received_packet.dstport
            msg.idle_timeout = 1200
            msg.hard_timeout = 1800
            
            # If the packet destinated to the honeypot, block the sender from sending any TCP traffic
            for connection in core.openflow.connections:
                connection.send(msg)
                core.getLogger("blocker").debug("installing flow for %s with destination port %i", ip_packet.srcip, Received_packet.dstport)
                core.getLogger("blocker").debug("blocked suspicious HTTP or SMB traffic %s <-> %s : wannacry self-propogation attempt", Received_packet.srcport, Received_packet.dstport)
            event.halt = True

            # handle HTTP requests
            if Received_packet.dstport == 80 or Received_packet.dstport == 443:
                HTTP_handler()
            
            # handle SMB requests
            if Received_packet.dstport == 445 or Received_packet.dstport == 139:
                SMB_handler()
    else:
        return

def launch():
    core.openflow.addListenerByName("PacketIn", HPM, priority=10000)
