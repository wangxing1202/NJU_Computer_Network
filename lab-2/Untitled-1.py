'''
Ethernet learning switch in Python.

Note that this file currently has the code to implement a "hub"
in it, not a learning switch.  (I.e., it's currently a switch
that doesn't learn.)
'''
import switchyard
from switchyard.lib.userlib import *

def main(net: switchyard.llnetbase.LLNetBase):
    my_interfaces = net.interfaces()
    mymacs = [intf.ethaddr for intf in my_interfaces]
    maclst = {}
    while True:
        try:
            _, fromIface, packet = net.recv_packet()
        except NoPackets:
            continue
        except Shutdown:
            break
        log_debug (f"In {net.name} received packet {packet} on {fromIface}")
        eth = packet.get_header(Ethernet)
        #{addr : [port,age]}
        port = my_interfaces[0]
        for intf in my_interfaces:
            if intf.name == fromIface:
                port = intf
                break
        for addr in maclst.keys():
            maclst[addr][1] += 1
        if eth.src in maclst:
            if port != maclst[eth.src][0]:
                maclst[eth.src][0] = port
        else:
            if(len(maclst) == 5):
                maclst=sorted(maclst,key = lambda k:maclst[k][1], reverse=False)
                del maclst[4]
            maclst[eth.src] = [port,0]
        
        if eth is None:
            log_info("Received a non-Ethernet packet?!")
            return
        if eth.dst in mymacs:
            log_info("Received a packet intended for me")
        else:
            if eth.dst in maclst.keys():
                intf = maclst[eth.dst][0]
                maclst[eth.dst][1] = 0
                net.send_packet(intf,packet)
            else:
                for intf in my_interfaces:
                    if fromIface!= intf.name:
                        log_info (f"Flooding packet {packet} to {intf.name}")
                        net.send_packet(intf, packet)

    net.shutdown()