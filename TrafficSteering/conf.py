#!/usr/bin/env python
# coding: utf-8

#Adresse IP Virtuelle
self.virtual_ip = "172.16.0.99"
self.virtual_mac = "CA:FE:00:00:BA:BE"

#Gateways (Renseigner uniquement les satellite gateways)
self.gateways = []
self.gateways.append({'ip':"172.16.0.1", 'mac':"00:7f:28:ff:3c:50", 'counter': 0}) #GW1
self.gateways.append({'ip':"172.16.0.2", 'mac':"00:34:03:b8:3a:cd", 'counter': 0}) #GW2

#Ports (Renseigner toutes les VM sur le bridge. Y compris GW déjàrenseignées)
self.mac_to_port = []
self.mac_to_port.append({'mac':"00:7f:28:ff:3c:50", 'port': 5}) #GW1 - vnet1
self.mac_to_port.append({'mac':"00:34:03:b8:3a:cd", 'port': 6}) #GW2 - vnet4
self.mac_to_port.append({'mac':"00:32:b7:66:50:40", 'port': 7}) #SP1 - vnet7
self.mac_to_port.append({'mac':"00:85:36:08:28:2b", 'port': 8}) #SP2 - vnet9
