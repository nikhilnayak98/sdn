from pox.core import core
import pox.lib.packet as pkt

def block_handler(event):
    tcp_packet = event.parsed.find('tcp')
    if tcp_packet is None:
        # if it isn't TCP, don't handle it
        return
    elif (tcp_packet.dstport == 445) or (tcp_packet.dstport == 139):
        core.getLogger("blocker").debug("Blocked TCP %s <-> %s", tcp_packet.srcport, tcp_packet.dstport)
        # halt the event
        event.halt = True
    else:
        return

def launch():
    core.openflow.addListenerByName("PacketIn", block_handler, priority=10000)