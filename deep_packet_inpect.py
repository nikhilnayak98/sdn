from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
from datetime import datetime

def DPI(event):
    tcp_packet = event.parsed.find('tcp') 
    # search for TCP.
    if tcp_packet is None:
        return
    # If the packet is not TCP, then do not handle it and return it to the forwarding.l2_learning component.
    elif (tcp_packet.dstport == 80 or tcp_packet.dstport == 445 or tcp_packet.dstport == 139):
     # If the packet is TCP, inspect the destination port for the ports 80, 445 or 139.
        packet = event.parsed
        # if the packet destination port is 80, 445 or 139 then parse the packet
        tcpbytes = tcp_packet.pack()
        if tcpbytes.find("infpub") != -1:
           detection_time = str(datetime.now())
           print("infpub has been found ! <-> BadRabbit Self-propagation attempt. At the time: ", detection_time)
           IP = event.parsed.find('ipv4')
           ipaddr = IP.srcip
           msg = of.ofp_flow_mod()
           # modify the flow table entries to add the following matching entries.
           msg.match.dl_type = 0x800
           # Match only with IPv4 packets as 0x800 is IPv4
           msg.match.dl_src = packet.src
           # Matching with the MAC address of the detected packet
           msg.match.nw_proto = 6
           # Matching with the TCP packets as 6 is TCP.
           msg.match.tp_dst = tcp_packet.dstport
           # Matching with the destination port of the detected packet.
           msg.idle_timeout = 1200
           # Apply this rule for 20 minutes.
           for connection in core.openflow.connections:
               connection.send(msg)
               core.getLogger("blocker").debug("flow has been installed for %s with destination port %i", IP.srcip, tcp_packet.dstport)
               core.getLogger("blocker").debug("Blocked Suspicious packet from port %s to port %s", tcp_packet.srcport, tcp_packet.dstport)
        else:
           # If infpub not found in the packet, forward the packet.
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
    core.openflow.addListenerByName("PacketIn", DPI, priority = 10000)