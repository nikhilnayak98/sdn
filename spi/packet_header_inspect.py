from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
from datetime import datetime

def PHI(event):
    # search for TCP packets
    tcp_packet = event.parsed.find('tcp')
    
   # if the packet is not TCP, then do not handle it and return it to the forwarding.l2_learning component
    if tcp_packet is None:
        return
    # else, inspect the destination port for the ports 139 and 445
    elif (tcp_packet.dstport == 139 or tcp_packet.dstport == 445):
        # parse the packet
        # convert the in-wire data to strings using pack function.
        tcpbytes = tcp_packet.pack()

        # search for the string ( NT LM 0.12) in the traffic
        if tcpbytes.find("NT LM 0.12") != -1:
           detection_time = str(datetime.now())
           print("NT LM 0.12 has been found ! <-> SMB version 1 attempt. At time: ", detection_time)
           # search for the IP version 4 fields in the packer
           ip_packet = event.parsed.find('ipv4')
           ipaddr = ip_packet.srcip
           msg = of.ofp_flow_mod()
           msg.match.dl_type = 0x800 
           msg.match_nw_src = ipaddr
           msg.match.nw_proto = 6
           msg.match.tp_dst = tcp_packet.dstport
           msg.idle_timeout = 1200
           msg.hard_timeout = 1800

           # install a rule to block the IP address of the sender
           for connection in core.openflow.connections:
               connection.send(msg)
               core.getLogger("blocker").debug("flow has been installed for %s with destination port %i", ip_packet.srcip, tcp_packet.dstport)
               core.getLogger("blocker").debug("blocked SMBv1 packet from port %s to port %s", tcp_packet.srcport, tcp_packet.dstport)
           event.halt = True
        else:
        # if the packet does not contain the string NT LM 0.12, forward it to the forwarding.l2_learning component in POX
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