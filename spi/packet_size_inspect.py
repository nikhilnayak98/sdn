# ./pox.py misc.full_payload forwarding.l2_learning packet_size_inspect samples.pretty_log log.level --DEBUG info.packet_dump

from pox.core import core
import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import tcp
from pox.lib.addresses import IPAddr, EthAddr
from datetime import datetime

# create a dictionary to put suspicious MAC addresses and threshold
packets = dict()

def PSI(event):
    sus_packet_sizes = [145, 250, 238]

    # search for TCP packets
    SMB_packet = event.parsed.find('tcp')
    
    if SMB_packet is None:
        return
    # check if its destination port is SMB port
    elif SMB_packet.dstport == 445:
        # parse the packet
        SMB_packet = event.ofp
        packet = event.parsed
        
        # get the size of the packet
        packet_size = len(SMB_packet)
        
        # if the packet size is suspicious, add MAC address to dictionary and increment threshold
        # then forward the packet to the forwarding.l2_learning component
        if packet_size in sus_packet_sizes:
            packets[packet.src] = packets.get(packet.src, 0) + 1
            print(packet.src, "has sent a SMB suspicious packets")
            
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            
            for connection in core.openflow.connections:
                connection.send(msg)
            event.halt = True

            # if threshold is more than 5, install a rule to block the packet source MAC address from communicating within the network
            if packets[packet.src] > 5:
                detection_time = str(datetime.now())
                print("suspicious smb packets found ! <-> sending three or more suspicious SMB packets. At time:", detection_time)

                msg = of.ofp_flow_mod()
                msg.match.dl_src = packet.src
                msg.idle_timeout = 1800
                msg.hard_timeout = 1800
                
                for connection in core.openflow.connections:
                    connection.send(msg)
                    core.getLogger("SMB Monitor").debug("blocked suspicious host with MAC address %s on port %i: sending three or more suspicious SMB packets", packet.src, event.port)
                event.halt = True
            else:
                return
        else: 
            msg = of.ofp_packet_out()
            msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
            msg.data = event.ofp
            msg.in_port = event.port
            for connection in core.openflow.connections:
                connection.send(msg)
            event.halt = True
    else:
        return
    
def launch():
    core.openflow.addListenerByName("PacketIn", PSI, priority = 10000)