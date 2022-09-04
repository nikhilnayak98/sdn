# ./pox.py misc.full_payload forwarding.l2_learning deep_packet_inspect samples.pretty_log log.level --DEBUG info.packet_dump

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
from datetime import datetime
import csv

# read suspicious strings from a csv file
suspicious_strings = []
with open('malicious_strings.csv', 'r') as read_obj:
    csv_reader = csv.reader(read_obj)
    list_of_rows = list(csv_reader)
    for rows in list_of_rows:
        suspicious_strings.append(rows[0])

def DPI(event):
    # ports to listen
    listening_ports = [139, 445]
    # search for TCP packets
    tcp_packet = event.parsed.find('tcp') 

    # if packet is not TCP return it to forwarding.l2_learning component
    if tcp_packet is None:
        return
    elif tcp_packet.dstport in listening_ports:
        # parse the packet
        packet = event.parsed
        tcpbytes = tcp_packet.pack()

        # check for suspicious strings
        for suspicious_string in suspicious_strings:
            if tcpbytes.find(suspicious_string) != -1: 
                detection_time = str(datetime.now())
                print("suspicious string has been found ! <-> wannacry self-propagation attempt. At time: ", detection_time)
                
                IP = event.parsed.find('ipv4')
                ipaddr = IP.srcip
                
                # modify flow table entries to add the following matching entries
                msg = of.ofp_flow_mod()
                
                msg.match.dl_type = 0x800                # match only with IPv4 packets as 0x800 is IPv4
                msg.match.dl_src = packet.src            # match with the MAC address of the detected packet
                msg.match.nw_proto = 6                   # match with the TCP packets as 6 is TCP
                msg.match.tp_dst = tcp_packet.dstport    # match with the destination port of the detected packet
                msg.idle_timeout = 1200                  # apply this rule for 20 minutes
                
                # install a rule to block IP address of the sender
                for connection in core.openflow.connections:
                    connection.send(msg)
                    core.getLogger("blocker").debug("flow has been installed for %s with destination port %i", IP.srcip, tcp_packet.dstport)
                    core.getLogger("blocker").debug("blocked suspicious packet from port %s to port %s", tcp_packet.srcport, tcp_packet.dstport) 
                break
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
