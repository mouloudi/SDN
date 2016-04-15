# VERSION QUI MARCHE BIEN ... Miracle. Peut etre parce qu'il s'agit de la v1.0 et que les docus ne sont pas retrocompatibles

# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
An OpenFlow 1.0 L2 learning switch implementation.
"""

import logging
import struct

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


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        #Preparation
        self.virtual_ip = "10.0.0.5"
        self.virtual_mac = "00:00:00:00:00:05"

        #Gateways
        self.gateways = []
        self.gateways.append({'ip':"10.0.0.2", 'mac':"00:00:00:00:00:02", 'port':2})
        self.gateways.append({'ip':"10.0.0.3", 'mac':"00:00:00:00:00:03", 'port':3})
        self.gateways.append({'ip':"10.0.0.4", 'mac':"00:00:00:00:00:04", 'port':4})

        self.index = 0


    def add_flow(self, datapath, in_port, dst, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port, dl_dst=haddr_to_bin(dst))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=5,
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

        dpid = datapath.id
        self.mac_to_port.setdefault(dpid, {})

        
        #Dans le cas ou on fait un requete ARP a l'IP virtuelle.
        if eth.ethertype == ether.ETH_TYPE_ARP:
            arp_hdr = pkt.get_protocols(arp.arp)[0]

            if arp_hdr.dst_ip == self.virtual_ip and arp_hdr.opcode == arp.ARP_REQUEST:
                reply_pkt = self.formulate_arp_reply(arp_hdr.src_mac, arp_hdr.src_ip)

                actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, 
                           in_port=msg.in_port, data=reply_pkt.data,
                           actions=actions, buffer_id = UINT32_MAX)
                datapath.send_msg(out)

                return
            #Il faut que les requetes ARP puissent circuler normalement
            else : 
                print "Requete ARP normale. On laisse passer"
                actions = [datapath.ofproto_parser.OFPActionOutput(ofproto.OFPP_FLOOD)]

                data = None
                if msg.buffer_id == ofproto.OFP_NO_BUFFER:
                    data = msg.data

                out = datapath.ofproto_parser.OFPPacketOut(
                    datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
                    actions=actions, data=data)
                datapath.send_msg(out)

                return

        elif eth.ethertype != ether.ETH_TYPE_IP:
            print "Paquet non IP. Rejete"
            return

        iphdr = pkt.get_protocol(ipv4.ipv4)
        #Paquet non destine a l'IP Virtuelle
        if not iphdr or (iphdr and iphdr.dst != self.virtual_ip) :
            return
      
        
        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        #On prepare le terrain pour rediriger le trafic vers la bonne GW
        currentGW = self.gateways[self.index % len(self.gateways)]
        #self.index = self.index + 1

        if currentGW["mac"] in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][currentGW["mac"]]
        else:
            out_port = ofproto.OFPP_FLOOD

        #DEBUG ONLY !!
        out_port = currentGW["port"]

        print ">>> GW choisie "+str(currentGW["mac"])+" ("+currentGW["ip"]+") - port : "+str(out_port)


        '''
            Paquet entrant vers la gateway. 
        '''
        #On modifie le header du paquet pour que la GW sache qu'il lui est destine
        '''actions = [datapath.ofproto_parser.OFPActionSetDlDst(dl_addr=currentGW["mac"]),
                   datapath.ofproto_parser.OFPActionSetNwDst(nw_addr=currentGW["ip"]),
                   datapath.ofproto_parser.OFPActionOutput(out_port)]'''

        actions = [datapath.ofproto_parser.OFPActionSetDlDst(dl_addr= haddr_to_bin(currentGW["mac"]) ),
                    datapath.ofproto_parser.OFPActionSetNwDst(nw_addr= self.ipv4_to_int(currentGW["ip"])),
                    datapath.ofproto_parser.OFPActionOutput(out_port)]
        
        '''  1.3 -> actions = [datapath.ofproto_parser.OFPActionSetField(eth_dst=currentGW["mac"]),datapath.ofproto_parser.OFPActionSetField(ipv4_dst=currentGW["ip"]), datapath.ofproto_parser.OFPActionOutput(out_port) ]'''

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, self.virtual_mac, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

        '''
            Paquet sortant depuis la gateway. 
        '''
        #On modifie le header du paquet pour que la SP pense que c'est l'IP Virtuelle qui a repondu.
        #(Pour que la correspondance socket puisse se faire)
        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(dl_addr= haddr_to_bin(self.virtual_mac)),
                   datapath.ofproto_parser.OFPActionSetNwSrc(nw_addr= self.ipv4_to_int(self.virtual_ip)),
                   datapath.ofproto_parser.OFPActionOutput(msg.in_port)]
        #actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port)]

        '''1.3 actions = [datapath.ofproto_parser.OFPActionSetField(eth_src=self.virtual_mac), datapath.ofproto_parser.OFPActionSetField(ipv4_src=self.virtual_ip), datapath.ofproto_parser.OFPActionOutput(msg.in_port)] '''

        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, out_port, src, actions)

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


    def ipv4_to_int(self,addr):
        ip = addr.split('.')
        assert len(ip) == 4
        i = 0
        for b in ip:
            b = int(b)
            i = (i << 8) | b
        return i
