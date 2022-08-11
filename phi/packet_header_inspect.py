from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
from datetime import datetime

def PHI(event):
    tcp_packet = event.parsed.find('tcp')
    # Search for TCP packets
    if tcp_packet is None:
        return
    # If the packet is not TCP, forward the packet to forwarding.l2_learning POX component
    elif (tcp_packet.dstport == 139 or tcp_packet.dstport == 445):
    # If the packet is TCP, match the destination port with the ports 139 and 445
        tcpbytes = tcp_packet.pack()
    # convert the in-wire data to strings using pack function.
        if tcpbytes.find("NT LM 0.12") != -1:
    # search for the string ( NT LM 0.12) in the traffic
           detection_time = str(datetime.now())
           print("NT LM 0.12 has been found ! <-> attmept to use SMB version 1 !!!. At the time: ", detection_time)
           ip_packet = event.parsed.find('ipv4')
           # search for the IP version 4 fields in the packer
           ipaddr = ip_packet.srcip
           msg = of.ofp_flow_mod()
           msg.match.dl_type = 0x800 
           msg.match_nw_src = ipaddr
           msg.match.nw_proto = 6
           msg.match.tp_dst = tcp_packet.dstport
           msg.idle_timeout = 1200
           msg.hard_timeout = 1800
           # Install a rule to block the IP address of the sender
           for connection in core.openflow.connections:
               connection.send(msg)
               core.getLogger("blocker").debug("flow has been installed for %s with destination port %i", ip_packet.srcip, tcp_packet.dstport)
               core.getLogger("blocker").debug("Blocked SMBv1 packet from port %s to port %s", tcp_packet.srcport, tcp_packet.dstport)
           event.halt = True
        else:
        # if the packet does not contain the string NT LM 0.12, forward it to the forwarding.l2_learning component in POX.
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
    core.openflow.addListenerByName("PacketIn", PHI, priority = 10000)