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

    def prefix_match(self, ipaddr):
        ipaddrs = [intf.ipaddr for intf in self.interfaces]
        if ipaddr not in ipaddrs:
            matches = [(i, entry[0].prefixlen) for i, entry in enumerate(self.ftable) if ipaddr in entry[0]]
            if matches:
                longest_match, _ = max(matches, key=lambda x: x[1])
                return longest_match
        return -1

    def send_arp(self,arp):
        for packet, intf, next_ip, _, _ in self.queue:
            if arp.senderprotoaddr == next_ip:
                eth_index = packet.get_header_index(Ethernet)
                packet[eth_index].src = intf.ethaddr
                packet[eth_index].dst = arp.senderhwaddr
                self.net.send_packet(intf.name ,packet)
                print("1")
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
                self.net.send_packet(intf.name,pkt)  
                print("2")
                self.queue.remove(item)
            elif time.time() - t > 1.0:
                if num >= 4:
                    self.queue.remove(item)
                else:
                    ether = Ethernet(src = intf.ethaddr,dst = "ff:ff:ff:ff:ff:ff",ethertype = EtherType.ARP)
                    arp = Arp(operation=ArpOperation.Request,
                            senderhwaddr=intf.ethaddr,
                            senderprotoaddr=intf.ipaddr,
                            targethwaddr="ff:ff:ff:ff:ff:ff",
                            targetprotoaddr=next_ip)
                    packet = ether+arp
                    item[3] = time.time()
                    item[4] += 1
                    self.net.send_packet(intf.name,packet)
                    print("3")
                    

    def print_arp_table(self):
        for key,value in self.arptable.items():
            print(key,":",value)
        print(" ")

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        # TODO: your logic here 
        arp = packet.get_header(Arp)
        ipv4 = packet.get_header_index(IPv4)
        if arp:
            if not any(intf.ipaddr == arp.targetprotoaddr for intf in self.interfaces):
                return#pass

            self.arptable[arp.senderprotoaddr] = arp.senderhwaddr
            self.print_arp_table()
            if arp.operation == ArpOperation.Reply:
                self.send_arp(arp)
            elif arp.operation == ArpOperation.Request:
                for intf in self.interfaces:
                    if arp.targetprotoaddr == intf.ipaddr:
                        Packet = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr)
                        self.net.send_packet(ifaceName,Packet)
                        log_debug("send packet {} to {}".format(packet, intf.name))
        
        
        elif ipv4:
            packet[ipv4].ttl -= 1
            if packet[ipv4].ttl <= 0:
                return
            ipv4 = packet[ipv4]
            index = self.prefix_match(ipv4.dst)
            if index == -1:
                return
            else:
                [_,next_ip,intfname] = self.ftable[index]
                #print(next_ip,intfname)
                intf = self.net.interface_by_name(intfname)
                if next_ip == IPv4Address('0.0.0.0'):
                    next_ip = ipv4.dst
                if next_ip != intf.ipaddr:
                    mac = self.arptable.get(next_ip)
                    if mac:
                        eth_index = packet.get_header_index(Ethernet)
                        packet[eth_index].src = intf.ethaddr
                        packet[eth_index].dst = mac 
                        self.net.send_packet(intfname, packet)
                        print("5")
                        self.arp_request_timer[next_ip] = time.time()
                    else:
                        self.queue.append([packet,intf,next_ip,time.time(),0])
                        if next_ip not in self.arp_request_timer:
                            arp_request = create_ip_arp_request(intf.ethaddr, intf.ipaddr, next_ip)
                            self.net.send_packet(intfname, arp_request) #find wrong? but how to fix
                            self.arp_request_timer[next_ip] = time.time()
                            print("6")

                        elif time.time() - self.arp_request_timer[next_ip] > 1:
                            return


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