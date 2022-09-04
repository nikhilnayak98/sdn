# ./pox.py forwarding.l2_learning arp_scan_monitor samples.pretty_log log.level --DEBUG info.packet_dump

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from datetime import datetime

# create a dictionary to put suspicious MAC addresses and threshold
arp_requests = dict()

def ASM(event):
    # define threshold
    threshold_value = 5

    # parse the packet
    packet = event.parsed

    # check if packet is ARP
    if packet.type == packet.ARP_TYPE:
        # ignore packet if destinated to 0.0.0.0
        if packet.payload.protosrc == IPAddr("0.0.0.0"):
            return
        # if packet is packet type request
        if packet.payload.opcode == arp.REQUEST: 
            # add MAC address to dictonary and increment the number of request
            arp_requests[packet.src] = arp_requests.get(packet.src, 0) + 1
            print(packet.payload.protosrc, "has performed", arp_requests[packet.src], "unanswered ARP reuqests.")
            
            # check for threshold
            if arp_requests[packet.src] > threshold_value:
                detection_time = str(datetime.now())
                print("suspicious arp packets found ! <-> sending three or more suspicious arp packets. At time: ", detection_time)

                ip_src = packet.src
                
                # modify flow table entries to add the following matching entries
                msg = of.ofp_flow_mod()
                msg.match.dl_src = packet.src
                msg.idle_timeout = 1800
                msg.hard_timeout = 1800
                
                # install a rule to block the packet source MAC address from communicating within the network
                for connection in core.openflow.connections:
                    connection.send(msg)
                    core.getLogger("ARP Requests Monitor").debug("blocked host with IP %s on port %i for 30 minutes", packet.payload.protosrc, event.port)
                    event.halt = True
            else:
                pass
        # check if packet type is reply
        elif packet.payload.opcode == arp.REPLY:
            # decrease the number of request by one of the MAC source address in the dictionary
            arp_requests[packet.dst] = arp_requests.get(packet.dst, 0) - 1
            print(packet.payload.protodst, "has performed", arp_requests[packet.dst], "unanswered ARP requests.")
        else:
            return
    else:
        return

def launch():
    arp_requests.clear()
    core.openflow.addListenerByName("PacketIn", ASM, priority = 20000)