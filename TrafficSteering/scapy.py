#!/usr/bin/env python
# coding: utf-8

'''
Realisé comme solution d'urgence et de secours.
Ne pas utiliser sauf cas extrème
'''

from scapy.all import *
import time
from thread import *
import os

'''
hosts.append("192.168.17.225")
hosts.append("192.168.17.209")
mainhost = "192.168.17.203"
'''

#Gateways 
hosts = []
hosts.append("172.0.16.1")
hosts.append("172.0.16.2")
mainhost = "172.0.16.5" #Host sur lequel le script tourne

currentGW = 0
lastIP = "";


def checkStatus() : 
    global currentGW
    # Chaque 3 secondes, on vérifie si le currentGW
    # répond correctement. Sinon, on bascule vers 
    # le prochain host
    while True:
        time.sleep(1)
        response = os.system("ping -c 1 " + str(hosts[currentGW])+" > /dev/null 2>&1")

        #Il y a un probleme
        if response != 0 :
            currentGW = (currentGW + 1) % len(hosts)
            print "Probleme ! On bascule vers "+str(hosts[currentGW])
        else : 
            print str(hosts[currentGW])+" up"

        #Y a deja eu du failover, on essaie de revenir vers la premiere plateforme
        if currentGW>0 :
            response = os.system("ping -c 1 " + str(hosts[currentGW-1])+" > /dev/null 2>&1")

            if response == 0 :
                print "Aha ! "+str(hosts[currentGW-1])+" a ressuscité ! On revient en arrière"
                currentGW = currentGW - 1


def steer(pkt) :
	global lastIP
	#Paquet sortant depuis l'une des gateways
	if pkt.haslayer("IP") and pkt["IP"].src in hosts :
		del pkt["IP"].chksum
		if pkt.haslayer(TCP) :
			del pkt["TCP"].chksum

		if not lastIP and not pkt.haslayer("ICMP"):
			print "Ah, Probleme ! La GW veut initialiser une connexion sortante"
		elif not pkt.haslayer("ICMP") :
			#print "Devenu "+str(pkt["IP"].src)+" -> "+str(pkt["IP"].dst)
			print "<<< Paquet envoyé par la GW "+str(pkt["IP"].src)+"->"+str(pkt["IP"].dst)+" devenant "+str(mainhost)+"->"+str(lastIP)
			pkt["IP"].src = mainhost
			pkt["IP"].dst = lastIP

			newpkt = pkt["IP"]
			send(newpkt)

	#Paquet entrant. Redirection vers l'une des gateways
	#if pkt.haslayer(TCP) == 1 and pkt["IP"].dst == mainhost and pkt['TCP'].dport == applicationPort :
	elif pkt.haslayer("IP") and pkt["IP"].dst == mainhost and (not pkt.haslayer("TCP") or (pkt.haslayer("TCP") and pkt['TCP'].dport != 22)) :
		del pkt["IP"].chksum

		if pkt.haslayer(TCP) :
			del pkt["TCP"].chksum

		lastIP = pkt["IP"].src
		#print "Devenu "+str(pkt["IP"].src)+" -> "+str(pkt["IP"].dst)
		print ">>> Paquet entrant "+str(pkt["IP"].src)+"->"+str(pkt["IP"].dst)+" devenant "+str(mainhost)+"->"+hosts[currentGW]
		pkt["IP"].src = mainhost
		pkt["IP"].dst = hosts[currentGW]

		newpkt = pkt["IP"]
		send(newpkt)


start_new_thread(checkStatus ,())
sniff(iface = "eth1", prn=steer, store=0)
