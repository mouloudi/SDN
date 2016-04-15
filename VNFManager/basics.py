'''
Include file. Contains basic functions and configuration stuff.
DO NOT RUN ALONE.
'''

import sys, os
import json
import socket
import subprocess
from thread import *


configFile = "/etc/vnfmdaemon.conf"

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
	elif (colorset == 4) : #Executing scripts
		msg = hilite(msg, 35, True)	

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



#Process status
def checkstatus(process):
	if not process :
		debug("ERROR. Unknown process name to watchdog. Quiting !", colorset=1)

	try :
		data = subprocess.check_output(['pgrep', process])
		return True
	except :
		return False
