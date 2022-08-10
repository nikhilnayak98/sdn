# Size_Checker.py
from pox.core import core
import pox.lib.packet as pkt
import pox.openflow.libopenflow_01 as of
from pox.lib.packet import tcp
from pox.lib.addresses import IPAddr, EthAddr
from datetime import datetime
packets = dict()
# Use the dict function to create a dictionary, so we can register the suspicious MAC addresses and the thershold in it.
suspicious_sizes = []
def size_inspector(event):
    SMB_packet = event.parsed.find('tcp')
    if SMB_packet is None:
       return 
   # search for tcp traffic, if it not TCP traffic, ignore it.
    elif(SMB_packet.dstport == 445):
   # if the traffic is TCP, match the destination port with the port 445
              SMB_packet = event.ofp
              packet = event.parsed
              packet_size = len(SMB_packet)
  # if the destination port is 445, get the size of the packet.
              if (packet_size == 145 or packet_size == 250 or packet_size == 238):
                 packets[packet.src] = packets.get(packet.src, 0) + 1 
                 print packet.src, "has sent a SMB suspicious packets"
                 suspicious_sizes.append(packet_size)
                 msg = of.ofp_packet_out()
                 msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
                 msg.data = event.ofp
                 msg.in_port = event.port
                 for connection in core.openflow.connections:
                     connection.send(msg)
                 event.halt = True
# if the packet size is 145, or 250, or 238 add the MAC address to the dictionary and increase the thershold to one. Then, forward the packet to the forwarding.l2_learning component.
                 if packets[packet.src] > 5:
                    msg = of.ofp_flow_mod()
                    msg.match.dl_src = packet.src
                    msg.idle_timeout = 1800
                    msg.hard_timeout = 1800
                    for connection in core.openflow.connections:
                        connection.send(msg)
                        core.getLogger("SMB Monitor").debug("Blocked host with MAC address %s on port %i: Sending three or more suspicious SMB packets", packet.src ,event.port)
                        detect_time = str(datetime.now())
                        print("Detection time is : ", detect_time)
                    event.halt = True
  # if the thershold is 5 or more, install a new rule to the switch to block the packet source MAC address from communicating within the network.
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
            # if the packet size is not suspicious forward it to the forwarding.l2_learning component.
    else:             
        print(suspicious_sizes) 
        return
    
def launch():
    core.openflow.addListenerByName("PacketIn", size_inspector, priority=10000)