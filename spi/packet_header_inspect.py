# ./pox.py forwarding.l2_learning packet_header_inspect samples.pretty_log log.level --DEBUG info.packet_dump

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
from datetime import datetime

def PHI(event):
    # suspicious headers
    sus_str0 = "PC NETWORK PROGRAM 1.0"
    sus_str1 = "LANMAN1.0"
    sus_str2 = "Windows for Workgroups 3.1a"
    sus_str3 = "LM1.2X002"
    sus_str4 = "NT LM 0.12"

    # search for TCP packets
    tcp_packet = event.parsed.find('tcp')

    # if packet is not TCP return it to forwarding.l2_learning component    
    if tcp_packet is None:
        return
    # inspect destination port for ports 139 or 445
    elif tcp_packet.dstport == 139 or tcp_packet.dstport == 445:
        # parse the packet
        tcpbytes = tcp_packet.pack()

        # check for suspicious strings
        if tcpbytes.find(sus_str0) != -1 or tcpbytes.find(sus_str1) != -1 or tcpbytes.find(sus_str2) != -1 or tcpbytes.find(sus_str3) != -1 or tcpbytes.find(sus_str4) != -1:
           detection_time = str(datetime.now())
           print("suspicious string found has been found ! <-> SMB version 1 attempt. At time: ", detection_time)
           
           # modify flow table entries to add the following matching entries
           ip_packet = event.parsed.find('ipv4')
           ipaddr = ip_packet.srcip
           msg = of.ofp_flow_mod()
           msg.match.dl_type = 0x800                    # match only with IPv4 packets as 0x800 is IPv4
           msg.match_nw_src = ipaddr
           msg.match.nw_proto = 6                       # match with the TCP packets as 6 is TCP
           msg.match.tp_dst = tcp_packet.dstport        # match with the destination port of the detected packet
           msg.idle_timeout = 1200                      # apply this rule for 20 minutes
           msg.hard_timeout = 1800

           # install a rule to block the IP address of the sender
           for connection in core.openflow.connections:
               connection.send(msg)
               core.getLogger("blocker").debug("flow has been installed for %s with destination port %i", ip_packet.srcip, tcp_packet.dstport)
               core.getLogger("blocker").debug("blocked SMBv1 packet from port %s to port %s", tcp_packet.srcport, tcp_packet.dstport)
           event.halt = True
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
    core.openflow.addListenerByName("PacketIn", PHI, priority = 10000)