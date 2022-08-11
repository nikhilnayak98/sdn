from pox.core import core
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
import pox.openflow.libopenflow_01 as of
from datetime import datetime

def DPI(event):
    sus_str0 = "h6agLCqPqVyXi2VSQ8O6Yb9ijBX54j"
    sus_str1 = "h54WfF9cGigWFEx92bzmOd0UOaZlM"
    sus_str2 = "tpGFEoLOU6+5I78Toh/nHs/RAP"

    # search for TCP packets
    tcp_packet = event.parsed.find('tcp') 

    # if the packet is not TCP, then do not handle it and return it to the forwarding.l2_learning component
    if tcp_packet is None:
        return
    # else, inspect the destination port for the ports 80, 445 or 139
    elif (tcp_packet.dstport == 80 or tcp_packet.dstport == 445 or tcp_packet.dstport == 139):
        # parse the packet
        packet = event.parsed
        tcpbytes = tcp_packet.pack()

        # check for suspicious strings
        if tcpbytes.find(sus_str0) != -1 or tcpbytes.find(sus_str1) != -1 or tcpbytes.find(sus_str2) != -1:
           detection_time = str(datetime.now())
           print("suspicious string has been found ! <-> wannacry self-propagation attempt. At time: ", detection_time)

           IP = event.parsed.find('ipv4')
           ipaddr = IP.srcip

           # modify the flow table entries to add the following matching entries
           msg = of.ofp_flow_mod()
           
           msg.match.dl_type = 0x800                # match only with IPv4 packets as 0x800 is IPv4
           msg.match.dl_src = packet.src            # match with the MAC address of the detected packet
           msg.match.nw_proto = 6                   # match with the TCP packets as 6 is TCP
           msg.match.tp_dst = tcp_packet.dstport    # match with the destination port of the detected packet
           msg.idle_timeout = 1200                  # apply this rule for 20 minutes

           # install a rule to block the IP address of the sender
           for connection in core.openflow.connections:
               connection.send(msg)
               core.getLogger("blocker").debug("flow has been installed for %s with destination port %i", IP.srcip, tcp_packet.dstport)
               core.getLogger("blocker").debug("blocked suspicious packet from port %s to port %s", tcp_packet.srcport, tcp_packet.dstport)
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
    core.openflow.addListenerByName("PacketIn", DPI, priority = 10000)