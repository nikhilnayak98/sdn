# ./pox.py forwarding.l2_learning honeypot_monitor samples.pretty_log log.level --DEBUG info.packet_dump

from pox.core import core
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
from pox.lib.addresses import IPAddr
from datetime import datetime

def HPM(event):
    # define ports
    listening_ports = [80, 443, 139, 445, 3389, 135, 5985, 5986, 20, 21, 3306, 25, 587, 993, 22, 23, 389, 636, 9389]
   
    # define honeypot address in the network
    honeypot_address = "192.168.1.7"

    # TODO: some of the ports communicate over UDP so write some code for UDP
    # search for TCP packets
    tcp_packet = event.parsed.find('tcp')
    
    if tcp_packet is None:
        return
    # check if destination port is in the listenting ports list
    elif tcp_packet.dstport in listening_ports:
        IP = event.parsed.find('ipv4')
        ipaddr = IP.dstip

        # match the destination IP with the honeypot IP
        if ipaddr == honeypot_address:
            ip_packet = event.parsed.find('ipv4')
            ipaddr = IP.srcip
            
            detection_time = str(datetime.now())
            print("suspicious connection found ! <-> connection to honeypot from " + str(ipaddr) + " to port " + str(tcp_packet.dstport) + ". At time: " + str(detection_time))
            
            # modify flow table entries to add the following matching entries
            msg = of.ofp_flow_mod()
            msg.match.dl_type = 0x800
            msg.match.nw_src = ipaddr
            msg.match.nw_proto = 6
            msg.match.tp_dst = tcp_packet.dstport
            msg.idle_timeout = 1200
            msg.hard_timeout = 1800
            
            # block the sender from sending any TCP traffic
            for connection in core.openflow.connections:
                connection.send(msg)
                core.getLogger("blocker").debug("installing flow for %s with destination port %i", ip_packet.srcip, tcp_packet.dstport)
                core.getLogger("blocker").debug("blocked suspicious traffic %s <-> %s : connection to honeypot", tcp_packet.srcport, tcp_packet.dstport)
            event.halt = True

            # handle HTTP requests
            if tcp_packet.dstport == 80 or tcp_packet.dstport == 443:
                print("A HTTP request to the Honeypot")
            # handle SMB requests
            elif tcp_packet.dstport == 445 or tcp_packet.dstport == 139:
                print("A SMB request to Honeypot")
            # handle Remote desktop protocol requests
            elif tcp_packet.dstport == 3389:
                print("A RDP request to Honeypot")
            # handle Remote procedure call requests
            elif tcp_packet.dstport == 135:
                rint("A RPC request to Honeypot")
            # handle Windows remote management requests
            elif tcp_packet.dstport == 5985 or tcp_packet.dstport == 5986:
                print("A Windows remote management request to Honeypot")
            # handle FTP requests
            elif tcp_packet.dstport == 20 or tcp_packet.dstport == 21:
                print("A FTP request to Honeypot")
            # handle SQL requests
            elif tcp_packet.dstport == 3306:
                print("A SQL request to the Honeypot")
            # handle Mail server requests
            elif tcp_packet.dstport == 25 or tcp_packet.dstport == 587 or tcp_packet.dstport == 993:
                print("A mail server related request to the Honeypot")
            # handle SSH requests
            elif tcp_packet.dstport == 22:
                print("A SSH request to the Honeypot")
            # handle Telnet requests
            elif tcp_packet.dstport == 23:
                print("A Telnet request to the Honeypot")
            # handle LDAP requests
            elif tcp_packet.dstport == 389 or tcp_packet.dstport == 636:
                print("A LDAP request to the Honeypot")
            # handle AD service requests
            elif tcp_packet.dstport == 9389:
                print("Active directory service requests to the Honeypot")
            else:
                pass
    else:
        return

def launch():
    core.openflow.addListenerByName("PacketIn", HPM, priority = 10000)
