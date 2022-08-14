# ./pox.py misc.full_payload forwarding.l2_learning dns_monitor samples.pretty_log log.level --DEBUG info.packet_dump

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
from pox.lib.packet.arp import arp
from datetime import datetime

def DNSMON(event):

    # parse the packet
    packet = event.parsed.find('dns')

    if packet is None:
        return
    elif packet.dstport == 53:
        

    # check if packet is ARP
    if packet.type == packet.ARP_TYPE:
        # ignore packet if destinated to 0.0.0.0
        if packet.payload.protosrc == IPAddr("0.0.0.0"):
            return
        # if packet is packet type request
        if packet.payload.opcode == arp.REQUEST: 
            # add MAC address to dictonary and increment threshold
            mydict[packet.src] = mydict.get(packet.src, 0) + 1
            print(packet.payload.protosrc, "has performed", mydict[packet.src], "unanswered ARP reuqests.")
            
            # if threshold is more than provided, install a rule to block the packet source MAC address from communicating within the network
            if mydict[packet.src] > threshold_value:
                detection_time = str(datetime.now())
                print("suspicious arp packets found ! <-> sending three or more suspicious arp packets. At time:", detection_time)

                ip_src = packet.src
                msg = of.ofp_flow_mod()
                msg.match.dl_src = packet.src
                msg.idle_timeout = 1800
                msg.hard_timeout = 1800
                
                for connection in core.openflow.connections:
                    connection.send(msg)
                    core.getLogger("ARP Requests Monitor").debug("blocked host with IP %s on port %i for 30 minutes", packet.payload.protosrc, event.port)
                    event.halt = True
            else:
                pass
        # check if packet type is reply
        elif packet.payload.opcode == arp.REPLY:
            # decrease one to MAC source address in the dictionary
            mydict[packet.dst] = mydict.get(packet.dst, 0) - 1
            print(packet.payload.protodst, "has performed", mydict[packet.dst], "unanswered ARP requests.")
        else:
            return
    else:
        return

def launch():
    mydict.clear()
    core.openflow.addListenerByName("PacketIn", DNSMON, priority = 10000)