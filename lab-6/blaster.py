#!/usr/bin/env python3

import time
from random import randint
import switchyard
from switchyard.lib.address import *
from switchyard.lib.packet import *
from switchyard.lib.userlib import *


class Blaster:
    def __init__(
            self,
            net: switchyard.llnetbase.LLNetBase,
            blasteeIp,
            num,
            length="100",
            senderWindow="5",
            timeout="300",
            recvTimeout="100"
    ):
        self.net = net
        # TODO: store the parameters
        self.blasteeIp = IPv4Address(blasteeIp)
        self.num = int(num)
        self.length = int(length)
        self.senderWindow = int(senderWindow)
        self.timeout = int(timeout)
        self.recvTimeout = int(recvTimeout)
        self.time = time.time()
        self.lhs = self.rhs = 0
        self.dict = {}
        self.retran = {}
        self.newpkt = {}
        self.begintime = self.begintime = 0
        self.retransmit = 0
        self.timeout_num = 0


    def create_packet(self, seq):
        packet = Ethernet(src='10:00:00:00:00:01', dst='40:00:00:00:00:01',ethertype=EtherType.IP)+IPv4(src='192.168.10.1',dst='192.168.10.1',protocol=IPProtocol.UDP)+UDP()
        packet+=RawPacketContents(seq.to_bytes(4,'big')+self.length.to_bytes(2,'big')+(0).to_bytes(self.length,'big'))
        return packet 
    

    def check_timeout_and_retransmit(self):
        if time.time() <= self.time + self.timeout:
            return

        self.retransmit += 1
        for temp in range(self.lhs, self.rhs + 1):
            if self.dict[temp][1] == 0:
                self.retran.append(self.dict[temp][0])
                self.retransmit += 1

        self.timeout_num += 1


    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        _, fromIface, packet = recv
        log_debug("I got a packet")
        sequence = int.from_bytes(packet[3].to_bytes()[:4], 'big')
        self.dict[sequence][1] = 1
        if sequence == self.lhs:
            while self.dict[self.lhs][1] == 1 and self.lhs <= self.rhs:
                self.lhs += 1
            if self.lhs > self.rhs and self.lhs < self.num:
                pkt = self.create_packet(self.lhs)
                self.newpkt.append(pkt)
                self.rhs = self.lhs
        
        if self.retran:
            self.net.send_packet(self.net.interfaces()[0], self.retran[0])
            del self.retran[0]
            if not self.retran:
                self.time = time.time()
            return
        else:
            if self.newpkt:
                self.net.send_packet(self.net.interfaces()[0], self.newpkt[0])
                self.newpkt.append([self.newpkt[0],0])
                del self.newpkt[0]
                self.time = time.time()
            elif self.rhs - self.lhs + 1 < self.senderWindow:
                self.rhs += 1
                pkt = self.create_packet(self.rhs)
                self.net.send_packet(self.net.interfaces()[0], pkt)
                self.append([pkt,0])
            return


    def handle_no_packet(self):
        log_debug("Didn't receive anything")
        if not self.retran:
            self.check_timeout_and_retransmit()
        if self.retran:
            self.net.send_packet(self.net.interfaces()[0], self.retran[0])
            del self.retran[0]
            if not self.retran:
                self.time = time.time()
        else:
            if self.newpkt:
                self.net.send_packet(self.net.interfaces()[0], self.newpkt[0])
                self.dict.append([self.newpkt[0],0])
                del self.newpkt[0]
                self.time = time.time()
            elif self.rhs - self.lhs + 1 < self.senderWindow:
                self.rhs += 1
                pkt = self.create_packet(self.rhs)
                self.net.send_packet(self.net.interfaces()[0], pkt)
                self.dict.append([pkt,0])
            return


    def start(self):
        '''A running daemon of the blaster.
        Receive packets until the end of time.
        '''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                self.handle_no_packet()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.shutdown()

    def shutdown(self):
        self.net.shutdown()


def main(net, **kwargs):
    blaster = Blaster(net, **kwargs)
    blaster.start()
