#!/usr/bin/env python
# coding: utf-8
"""
An OpenFlow 1.0 L2 Trafic-steering implementation.
"""

import logging
import struct
import time
import os
from thread import *

from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0, ether, inet
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import tcp
from ryu.lib.packet import ipv4

UINT32_MAX = 0xffffffff


TIMEOUT_SWITCH = 9 #In seconds. Timeout after what we check about the gateway. MUST BE MORE THAN TIMEOUT_FLOWMOD
TIMEOUT_FLOWMOD = 3 #In seconds. Timeout after what the flow is deleted and OVS check for new instructions.

class TraficSteering(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def checkStatus(self) : 
        while True:
            time.sleep(TIMEOUT_SWITCH)
            response = os.system("ping -c 1 " + str(self.gateways[self.currentGWindex]["ip"])+" > /dev/null 2>&1")

            #Il y a un probleme
            if response != 0 :
                self.currentGWindex += 1
                self.currentGWindex %= len(self.gateways)

                print "/!\ Gateway switch vers "+self.gateways[self.currentGWindex]["ip"]
            else : 
                print "RAS pour la GW "+str(self.gateways[self.currentGWindex]["ip"])



    def __init__(self, *args, **kwargs):
        super(TraficSteering, self).__init__(*args, **kwargs)

        #Preparation
        self.virtual_ip = "172.16.0.99"
        self.virtual_mac = "CA:FE:00:00:BA:BE"
        self.currentGWindex = 0

        #Gateways (Renseigner que les GW)
        self.gateways = []
        self.gateways.append({'ip':"172.16.0.1", 'mac':"00:7f:28:ff:3c:50", 'counter': 0}) #GW1
        self.gateways.append({'ip':"172.16.0.2", 'mac':"00:34:03:b8:3a:cd", 'counter': 0}) #GW2

        #Ports (Renseigner tous ceux sur le bridge. Y compris GW)
        self.mac_to_port = []
        self.mac_to_port.append({'mac':"00:7f:28:ff:3c:50", 'port': 5}) #GW1 - vnet1
        self.mac_to_port.append({'mac':"00:34:03:b8:3a:cd", 'port': 6}) #GW2 - vnet4
        self.mac_to_port.append({'mac':"00:32:b7:66:50:40", 'port': 7}) #SP1 - vnet7
        self.mac_to_port.append({'mac':"00:85:36:08:28:2b", 'port': 8}) #SP2 - vnet9

        start_new_thread(self.checkStatus ,())


    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=TIMEOUT_FLOWMOD,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src

        # Autoriser tous les paquets non destines a la MAC virtuelle
        if dst.lower() != self.virtual_mac.lower() :
            #print "Trame : "+str(src)+" -> "+str(dst)

            #Enregistrer l'activite des GW
            localindex = 0
            for gw in self.gateways :
                if src == gw["mac"] :
                    self.gateways[localindex]["counter"] += 1
                    break
                localindex += 1
 

            #Resolution du port sortant
            outport = ofproto.OFPP_FLOOD
            for machine in self.mac_to_port :
                if machine["mac"] == dst :
                    outport = machine["port"]
                    break

            actions = [datapath.ofproto_parser.OFPActionOutput(outport)]

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)

            return

        else : 
            #On redirige le trafic vers la bonne GW
            currentGW = self.gateways[self.currentGWindex]

            for gw in self.mac_to_port :
                if gw["mac"] == currentGW["mac"] :
                    outport = gw["port"]
                    break

            if not outport : 
                print "ERROR. No port found for the choosen gateway"
                return

            print ">>> GW choisie "+str(currentGW["mac"])+" ("+currentGW["ip"]+") - port : "+str(outport)

            actions = [datapath.ofproto_parser.OFPActionSetDlDst(dl_addr= haddr_to_bin(currentGW["mac"])),
                        datapath.ofproto_parser.OFPActionOutput(outport)]
            
            self.add_flow(datapath, msg.in_port, self.virtual_mac, actions)

            data = None
            if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                data = msg.data

            out = datapath.ofproto_parser.OFPPacketOut(
                datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                actions=actions, data=data)
            datapath.send_msg(out)

        

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)


    def formulate_arp_reply(self, dst_mac, dst_ip):
        print "Fool ARP "+str(self.virtual_mac)
        if self.virtual_ip == None:
            return

        src_mac = self.virtual_mac
        src_ip = self.virtual_ip
        arp_opcode = arp.ARP_REPLY
        arp_target_mac = dst_mac

        ether_proto = ether.ETH_TYPE_ARP
        hwtype = 1
        arp_proto = ether.ETH_TYPE_IP
        hlen = 6
        plen = 4

        pkt = packet.Packet()
        e = ethernet.ethernet(dst_mac, src_mac, ether_proto)
        a = arp.arp(hwtype, arp_proto, hlen, plen, arp_opcode,
                    src_mac, src_ip, arp_target_mac, dst_ip)
        pkt.add_protocol(e)
        pkt.add_protocol(a)
        pkt.serialize()

        return pkt
