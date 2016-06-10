#!/usr/bin/env python
# coding: utf-8

'''
PackageHandler V1 :
- Receive and install the VNF Packages.
- Performs the events rules specified in the lifecycle config file.
'''

import random
import tarfile
from shutil import copyfile

#Basics scripts and importation
execfile("basics.py")

#Script copied from http://stackoverflow.com/questions/12791997/how-do-you-do-a-simple-chmod-x-from-within-python
def make_executable(path):
    mode = os.stat(path).st_mode
    mode |= (mode & 0o444) >> 2
    os.chmod(path, mode)


#Return an array filled with names of the vnf packages (available at config["VNFPKGDIR"]+)
def GetVNFPackageNames() :
	if not os.path.exists(config["VNFPKGDIR"]):
		os.makedirs(config["VNFPKGDIR"])

	names = []
	for vnfname in os.listdir(config["VNFPKGDIR"]):
		names.append(vnfname)
	return names

#Execute scripts for a specific VNF. Event must be either START or TERMINATE.
def ExecuteScripts(vnfpackage,event) :
	if event != "START" and event != "TERMINATE" :
		debug("ERROR. Event must be either START or TERMINATE.")
	else :
		debug(">> Executing "+event.lower()+" scripts for "+vnfpackage,colorset=4)
		try : 
			for scripts in os.listdir(config["VNFPKGDIR"]+"/"+vnfpackage+"/"+event+"/"):
				os.system(config["VNFPKGDIR"]+"/"+vnfpackage+"/"+event+"/"+scripts)
		except Exception, e:
			debug("WARNING : "+str(e), colorset=1)


#Run VNF scripts on startup
def StartupScripts(specificVNF=0) :
	VNFPackages = GetVNFPackageNames()
	for i in range (0, len(VNFPackages)) :
		ExecuteScripts(VNFPackages[i], "START")


#Run VNF scripts when a specifi
def EventScripts() :
	VNFPackages = GetVNFPackageNames()
	processes = []

	#Processes indexes are the same that VNFPackages
	for i in range (0, len(VNFPackages)) :
		processes.append([])
		try : 
			with open(config["VNFPKGDIR"]+"/"+VNFPackages[i]+"/lifecycle.json") as data_file :
				jsondata = json.load(data_file)
				processName = str(jsondata["VNFprocess"])
				processes[i].append(processName)

				#Checkstatus
				processes[i].append(checkstatus(processName))
		except Exception, e:
			debug("WARNING : "+str(e), colorset=1)

	while True :
		for i in range (0, len (processes)) :
			#The process was running in the previous iteration and it's not anymore
			if processes[i][1] == True and checkstatus(processes[i][0]) == False :
				processes[i][1] = False
				ExecuteScripts(VNFPackages[i],"TERMINATE")

			elif processes[i][1] == False and checkstatus(processes[i][0]) == True :
				processes[i][1] = True
				ExecuteScripts(VNFPackages[i],"START")
	

#VNF Package handler
def multiplesocket(connection) :
	try :
		#Reception
		rand = random.randint(0,100000000)
		tmpFileName = "/tmp/"+str(rand)+".tar.gz"
		tmpTarFile = open(tmpFileName,'wb')

		debug("Receiving ...",colorset=3)
		while True :
			data = connection.recv(1500)
			if not data :
				break
			tmpTarFile.write(data)

		tmpTarFile.close()
		debug("Reception done.",colorset=3)

		#Untarring
		tarFile = tarfile.open(tmpFileName)
		tarFile.extractall("/tmp/"+str(rand))
		tarFile.close()

		#JSON Analyze
		if not os.path.isfile("/tmp/"+str(rand)+"/lifecycle.json") :
			debug("ERROR. lifecycle.json not found", colorset=1)
			connection.send("ERROR. lifecycle.json not found.")
		else :
			with open("/tmp/"+str(rand)+"/lifecycle.json") as data_file:    
				jsondata = json.load(data_file)

			lifecycle = jsondata["lifecycle_event"]
			VNFPackagename = jsondata["name"]

			#Prepare other scripts
			for i in range(0,len(lifecycle)) :
				if (lifecycle[i]["event"] == "INSTANTIATE") :
					INSTANTIATE = lifecycle[i]["lifecycle_events"]
				elif (lifecycle[i]["event"] == "START") :
					START = lifecycle[i]["lifecycle_events"]
				elif (lifecycle[i]["event"] == "TERMINATE") :
					TERMINATE = lifecycle[i]["lifecycle_events"]

			#Preparing scripts dir
			if not os.path.exists(config["VNFPKGDIR"]):
				os.makedirs(config["VNFPKGDIR"])

			try :
				debug("Preparing VNF "+VNFPackagename,colorset=2)
				os.makedirs(config["VNFPKGDIR"]+"/"+VNFPackagename+"/START")
				os.makedirs(config["VNFPKGDIR"]+"/"+VNFPackagename+"/TERMINATE")
				copyfile("/tmp/"+str(rand)+"/lifecycle.json",config["VNFPKGDIR"]+"/"+VNFPackagename+"/lifecycle.json")
			except Exception,e :
				debug("WARNING : VNF Package already exists : "+VNFPackagename,colorset=1)

			#Go go go ! 
			#First scripts to be executed are in the INSTANTIATE rule
			if INSTANTIATE :
				for i in range(0,len(INSTANTIATE)) :
					if not os.path.isfile("/tmp/"+str(rand)+"/"+START[i]) :
						debug("ERROR. File not found : "+START[i], colorset=1)
					else :
						make_executable("/tmp/"+str(rand)+"/"+INSTANTIATE[i])

						debug("Executing "+INSTANTIATE[i],colorset=2)
						os.system("/tmp/"+str(rand)+"/"+INSTANTIATE[i])

			#Scripts to be executed on VM's startup
			if START :
				for i in range(0,len(START)) :
					if not os.path.isfile("/tmp/"+str(rand)+"/"+START[i]) :
						debug("ERROR. File not found : "+START[i], colorset=1)
					else :
						copyfile("/tmp/"+str(rand)+"/"+START[i],config["VNFPKGDIR"]+"/"+VNFPackagename+"/START/"+START[i])
						make_executable(config["VNFPKGDIR"]+"/"+VNFPackagename+"/START/"+START[i])

			#And those to be executed on VNF termination
			if TERMINATE :
				for i in range(0,len(TERMINATE)) :
					if not os.path.isfile("/tmp/"+str(rand)+"/"+TERMINATE[i]) :
						debug("ERROR. File not found : "+TERMINATE[i], colorset=1)
					else :
						copyfile("/tmp/"+str(rand)+"/"+TERMINATE[i],config["VNFPKGDIR"]+"/"+VNFPackagename+"/TERMINATE/"+TERMINATE[i])
						make_executable(config["VNFPKGDIR"]+"/"+VNFPackagename+"/TERMINATE/"+TERMINATE[i])


			debug("Installation completed",colorset=2)

	except Exception, e: 
		debug("ERROR. Reason : "+str(e), colorset=1)
		reply = "ERROR. "+str(e)
		connection.send(reply)
	finally :
		connection.close()

#Here we finally start !
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('', config["PORTVP"]))
sock.listen(config["QUEUEDCNXS"])

#Scripts that've to be run on startup/termination of VNFs
start_new_thread(EventScripts ,())

while True:
	try :
		#Waiting a VNF Package to be sent
		client, address = sock.accept()
		debug('CONNECTED : ' + address[0] + ':' + str(address[1]))
		start_new_thread(multiplesocket ,(client,))

	except Exception, e:
		debug("ERROR. Brutal closing. Reason : "+str(e), colorset=1)

		client.close()
		sock.close()
		sock.shutdown()

		break
