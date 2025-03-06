#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.userlib import *
from switchyard.lib.address import *

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.arptable = {}
        self.interfaces = self.net.interfaces()
        self.ftable = []
        self.queue = []
        # other initialization stuff here
        self.arp_request_timer = {}
        self.fintf = " "

    def prefix_match(self,ipaddr):
        ipaddrs = [intf.ipaddr for intf in self.interfaces]
        if ipaddr not in ipaddrs:
            match = [(i, entry[0].prefixlen) for i, entry in enumerate(self.ftable) if ipaddr in entry[0]]
            if match:
                longest_match, _ = max(match, key=lambda x: x[1])
                return longest_match
        return -1

    def send_arp(self,arp):
        for packet, intf, next_ip, _, _ in self.queue:
            if arp.senderprotoaddr == next_ip:
                eth_index = packet.get_header_index(Ethernet)
                packet[eth_index].src = intf.ethaddr
                packet[eth_index].dst = arp.senderhwaddr
                self.net.send_packet(intf.name ,packet)
                for temp in self.queue:
                    if temp[0] == packet:
                        self.queue.remove(temp)
                        break

    def forward(self):
        for pkt, intf, next_ip, t, num in self.queue:
            for item in self.queue:
                if item[0] == pkt:
                    break
            if next_ip in self.arptable.keys():
                eth_index = pkt.get_header_index(Ethernet)
                pkt[eth_index].dst = self.arptable[next_ip]
                pkt[eth_index].src = intf.ethaddr
                ipv4 = pkt.get_header(IPv4)
                self.net.send_packet(intf.name,pkt)  
                self.queue.remove(item)
            elif time.time() - t > 1.0:
                print(num)
                if num >= 5:
                    if pkt.get_header_index(ICMP):
                        ip = self.net.interface_by_name(self.fintf).ipaddr
                        ipv4 = pkt.get_header(IPv4)
                        pkt = self.create_ICMP_packet(ICMPType.DestinationUnreachable,1,pkt,ip,ipv4.src,len(pkt))
                        src_index = self.prefix_match(ipv4.src)
                        self.process_packet(src_index,pkt,ipv4.src)
                    self.queue.remove(item)
                else:
                    ether = Ethernet(src = intf.ethaddr,dst = "ff:ff:ff:ff:ff:ff",ethertype = EtherType.ARP)
                    arp = Arp(operation=ArpOperation.Request,
                            senderhwaddr=intf.ethaddr,
                            senderprotoaddr=intf.ipaddr,
                            targethwaddr='ff:ff:ff:ff:ff:ff',
                            targetprotoaddr=next_ip)
                    arppacket = ether+arp
                    item[3] = time.time()
                    item[4] += 1
                    print(intf.name,item[2])
                    self.net.send_packet(intf.name,arppacket)
                    print("finish request")
                    

    def create_ICMP_packet(self,Type,Code,pkt,src,dst,len):
        i = pkt.get_header_index(Ethernet)
        del pkt[i]
        icmp = ICMP()
        icmp.icmptype = Type
        icmp.icmpcode = Code
        icmp.icmpdata.data = pkt.to_bytes()[:28]
        icmp.icmpdata.origdgramlen = len
        ip = IPv4()
        ip.protocol = IPProtocol.ICMP
        ip.ttl = 32
        ip.src = src
        ip.dst = dst
        packet = Ethernet() + ip + icmp
        return packet

    def print_arp_table(self):
        for key,value in self.arptable.items():
            print(key,":",value)
        print(" ")


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here
        self.fintf = ifaceName
        arp = packet.get_header(Arp)
        ipdx = packet.get_header_index(IPv4)
        if arp:
            if not any(intf.ipaddr == arp.targetprotoaddr for intf in self.interfaces):
                return#pass
            self.arptable[arp.senderprotoaddr] = arp.senderhwaddr
            #self.print_arp_table()
            if arp.operation == ArpOperation.Request:
                for intf in self.interfaces:
                    if arp.targetprotoaddr == intf.ipaddr:
                        Packet = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr)
                        self.net.send_packet(ifaceName,Packet)
                        log_debug("send packet {} to {}".format(packet, intf.name))
            elif arp.operation == ArpOperation.Reply:
                self.send_arp(arp)

        elif ipdx:
            eth = packet[Ethernet]
            if eth.ethertype != EtherType.IPv4:
                return
            packet[ipdx].ttl -= 1
            ipv4 = packet[ipdx]
            icmp_idx = packet.get_header_index(ICMP)
            src = self.net.interface_by_name(ifaceName).ipaddr
            dst = ipv4.src
            src_index = self.prefix_match(ipv4.src)
            dst_index = self.prefix_match(ipv4.dst)

            if ipv4.dst in [intf.ipaddr for intf in self.interfaces]:
                if icmp_idx != -1 and packet[icmp_idx].icmptype == ICMPType.EchoRequest:
                    ipv4.dst,ipv4.src = ipv4.src,ipv4.dst
                    temp = ICMP(icmptype = ICMPType.EchoReply)
                    temp.icmpdata.sequence = packet[icmp_idx].icmpdata.sequence
                    temp.icmpdata.identifier = packet[icmp_idx].icmpdata.identifier
                    temp.icmpdata.data = packet[icmp_idx].icmpdata.data
                    packet[icmp_idx] = temp
                    self.process_packet(src_index,packet,ipv4.dst)
                elif icmp_idx == -1:
                    packet = self.create_ICMP_packet(ICMPType.DestinationUnreachable,3,packet,src,dst,len(packet))
                    self.process_packet(src_index,packet,dst)
                    
            elif packet[ipdx].ttl <= 0:
                packet = self.create_ICMP_packet(ICMPType.TimeExceeded,0,packet,src,dst,len(packet))
                self.process_packet(src_index,packet,dst)

            elif dst_index != -1:
                self.process_packet(dst_index,packet,ipv4.dst)
            else:
                packet = self.create_ICMP_packet(ICMPType.DestinationUnreachable,0,packet,src,dst,len(packet))
                self.queue.append([packet,self.net.interface_by_name(ifaceName),dst,time.time(),0])
            return


    def process_packet(self,index,packet,dstip):
        next_ip = self.ftable[index][1]
        if next_ip == IPv4Address('0.0.0.0'):
            next_ip = dstip
        eth_index = packet.get_header_index(Ethernet)
        #print(next_ip)
        intfname = self.ftable[index][2]
        intf = self.net.interface_by_name(intfname)
        packet[eth_index].src = intf.ethaddr
        #print(intfname)
        if next_ip in self.arptable.keys():
            packet[eth_index].dst = self.arptable[next_ip]#mac 
            self.net.send_packet(intfname, packet)
        else:
            self.queue.append([packet,self.net.interface_by_name(intfname),next_ip,time.time(),0])

    def build_ftable(self):
        for intf in self.interfaces:
            entry = [
                IPv4Network(f"{intf.ipaddr}/{intf.netmask}", False),
                IPv4Address("0.0.0.0"),
                intf.name
            ]
            self.ftable.append(entry)

        with open("forwarding_table.txt", "r") as f:
            for line in f:
                line = line.strip()
                network, netmask, next_hop, interface = line.split(" ", 4)
                entry = [
                    IPv4Network(f"{network}/{netmask}"),
                    IPv4Address(next_hop),
                    interface
                ]
                self.ftable.append(entry)


    def start(self):
        '''A running daemon of the router.
        Receive packets until the end of time.
        '''
        self.build_ftable()
        for item in self.ftable:
            log_info(item)
        while True:
            self.forward()
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)             

        self.stop()

    def stop(self):
        self.net.shutdown()


def main(net):
    '''
    Main entry point for router.  Just create Router
    object and get it going.
    '''
    router = Router(net)
    router.start()