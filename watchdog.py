#!/usr/bin/env python
# coding: utf-8

'''
V3 Changelog : 
- Multithreading integration for a multiple socket capability.
- Catching all signals from the subprocess function that may disturbe
	the server-side shell when some programs are launched remotly (nano for instance)
- Some bugs were fixed (Especially the one that was sending the same packet 
	to all opened sockets).
- Auto close previous and remaining sockets (may happen when the daemon is 
	force-closed)

Run this script as root for better control.
'''

import socket
import subprocess
import sys, os
import json

from thread import *

configFile = "/etc/watchdog.conf"

if not os.path.isfile(configFile) :
	print "No configuration file found in "+configFile
	sys.exit()



config = {}
execfile(configFile,config)
DEBUG = config["DEBUG"]

for arg in sys.argv :
	if arg == "-debug" :
		DEBUG = True


#Debugging
lastlineerased = False
def debug(msg, colorset = 0, progress=False) :
	global lastlineerased

	if (colorset == 1) : #Error
		msg = hilite(msg, 31, True)
	elif (colorset == 2) : #Status
		msg = hilite(msg, 32, True)	
	elif (colorset == 3) : #Receiving file progression
		msg = hilite(msg, 33, False)	

	if (DEBUG) :
		if (progress) :
			lastlineerased = True
			CURSOR_UP_ONE = '\x1b[1A'
			ERASE_LINE = '\x1b[2K'
			print(CURSOR_UP_ONE + ERASE_LINE + CURSOR_UP_ONE)
		
		print msg

#Coloring shell
def hilite(string, colorid, bold):
	attr = []
	attr.append(str(colorid))

	if bold:
		attr.append('1')

	return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), string)

#WatchingDog the process
def watchdog():
	if not config["PTW"] :
		debug("ERROR. Unknown process name to watchdog. Quiting !", colorset=1)

	try :
		data = subprocess.check_output(['pgrep', config["PTW"]])
		return True
	except :
		return False




def processData(packet):

	'''               
                      ********* PACKET STRUCTURE *********
	 _________________
	|        |        |--------------------------------------------------
	| Paquet | Paquet |  VNF ID ?  |  Version  | Code inst. | Extra data |
	|   IP   |  TCP   |  (1 byte)  |  (1 byte) |  (1 byte)  |   (JSON)   |
	|________|________|--------------------------------------------------

	VNF ID [NOT YET IMPLEMENTED] −> In case it's the controller who'll redirect the query.
	Version -> 0x01
	Instructions -> 0x01 (Status)
					0x10 (File Push)
					0x11 (File delete)
					0x12 (Execute)
	'''


	reply = ""
	shutdownImmediatly = False
	if not packet : 
		return


	''' STEP 1 : Parsing data '''
	try :
		vers = int(packet[0].encode("hex"))
		inst = int(packet[1].encode("hex"))
	except : 
		debug("ERROR. Incoherent data received. Quiting !", colorset=1)

	#For instructions >0x10, there is JSON data embeded
	if inst >= 0x10 :
		try : 
			payload = packet[2:]
			payload = payload.replace("'",'"')
			payload = payload.replace("\/","/")

			#Base64 default
			payload = payload.replace('\n','\\n')
			#print payload
			jsonObject = json.loads(payload)
		except :
			debug("ERROR. Incoherent data received. Quiting !", colorset=1)
			return


	''' STEP 2 : Do what you're asked for '''
	#STATUS
	if inst == 0x01 : 
		debug("INSTRUCTION : Status", colorset=2)

		if watchdog() :
			reply = "RUNNING"
		else :
			reply = "DOWN"
	
	#FILE PUSH
	elif inst == 0x10:

		nameFile = jsonObject[0]["file"]
		content = jsonObject[0]["content"]
		window = jsonObject[0]["window"]
		totalParts = jsonObject[0]["totalparts"]

		progressPercent = "{0:.2f}".format(100 * float(window) / float(totalParts))
		debug("INFO : Receiving "+str(nameFile)+" in progress ("+progressPercent+"%)", progress=True, colorset=3)

		try : 
			reply = "OK"
			fileWriting = open(nameFile,'ab')
			fileWriting.write(content.decode("base64"))
			fileWriting.close()
		except Exception,e: 
			reply = "ERROR. "+str(e)
			debug("ERROR. Unable to write file. Reason : "+str(e), colorset=1)
	
	#FILE DELETE
	elif inst == 0x11:
		debug("INSTRUCTION : File delete")
		nameFile = jsonObject[0]["file"]

		if not os.path.isfile(nameFile) :
			reply = "ERROR. File not found."
		else :
			try :
				reply = "DELETED"
				os.remove(nameFile)
			except Exception, e:
				reply = "ERROR. Unable to delete. Reason : "+str(e)

	#EXECUTE
	elif inst == 0x12:
		debug("INSTRUCTION : Execute")
		cmd = jsonObject[0]["cmd"]
		execOutput, execError = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE).communicate()
				
		if execError :
			reply = "ERROR. "+execError
			if execOutput :
				reply += "\n>> However, there is a stdout stream >>\n\n"+execOutput
		else :
			reply = execOutput

		shutdownImmediatly = True

	else :
		debug("ERROR. Unknown instruction. Maybe an incompatible version between client and server ?", colorset=1)



	''' STEP 3 : Reply, if there is one. '''
	if reply :
		return (reply, shutdownImmediatly)




def multiplesocket(connection) :
	#Be polite and say hi to the client !
	connection.send('Connected !')

	try :
		data = connection.recv(1500)
		while data :
			response, reaction = processData(data)
			if response : 
				connection.send(response)

				if reaction :
					connection.shutdown()

			del data
			data = connection.recv(1500)
	except TypeError, e:
		pass
	except Exception, e: 

		debug("ERROR. Reason : "+str(e), colorset=1)
		reply = "ERROR. "+str(e)
		connection.send(reply)
	finally :
		connection.close()

#Here we finally start !
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', config["PORTWD"]))
sock.listen(config["QUEUEDCNXS"])

while True:
	try :
		client, address = sock.accept()
		debug('CONNECTED : ' + address[0] + ':' + str(address[1]))
		start_new_thread(multiplesocket ,(client,))

	except Exception, e:
		debug("ERROR. Brutal closing. Reason : "+str(e), colorset=1)

		client.close()
		sock.close()
		sock.shutdown()

		break
