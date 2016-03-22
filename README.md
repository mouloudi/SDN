# Introduction

The VNF Manager is composed by two daemons : 

- A main daemon that receives basic requests and could be asked :
	* About the status of a process (which is in fact the VNF)
	* To delete or upload a file  
	* To execute a line of code

- A daemon that receives and processes VNF packages. A VNF package is 
an archive that contains scripts and all information required to run a
VNF.

These daemons can be executed simultaneously thanks to "executor.sh"
included in this repository. 
Just run it as root for a better control.



# Prepare a VNF Package

The package must contains a lifecycle.json file with this structure : 

```javascript
{
    "name" : "NameOfTheVNF",
    "VNFprocess" : "ProcessName",
    "lifecycle_event":[{
        "event":"INSTANTIATE",
        "lifecycle_events":[
            "install.sh",
            "configure.sh"
        ]
    },
    {
        "event":"START",
        "lifecycle_events":[
             "start.sh"
        ]
    },
    {
        "event":"TERMINATE",
        "lifecycle_events":[
             "terminate.sh"
        ]
    }]
}
```

- **name** attribute must be alphanumeric without spaces. You're free to choose
the name you want.

- **VNFprocess** attribute must match a Linux process to watch. The upcoming events will
be based on the status of this process (whether it's running or not).

- The **lifecycle_events** attributes regroups the name of the scripts files that
will be executed when a specific event occurs : 
	* The scripts files specified under the "INSTANTIATE" event will be launched
	when the VNF package is set for the first time. (Once the archive is untarred)
	* Files under the *START* event will be launched when the process of the VNF 
	(specified in the **VNFprocess** attribute) is launched.
	* Files under the *TERMINATE* event will be launched when the process of the VNF 
	(specified in the **VNFprocess** attribute) is not anymore running.

You can omit one or more events if you don't need them.


The structure of the tar-ball will looks like :
|-- lifecycle.json
|-- install.sh
|-- configure.sh
|-- start.sh
|-- terminate.sh

Obviously, it could also contains one or more packages that will be installed
with a dpkg command available in the "install.sh" file.



# Changelogs

Main daemon V3 Changelog : 
- Multithreading integration for a multiple socket capability.
- Catching all signals from the subprocess function that may disturbe
	the server-side shell when some programs are launched remotly (nano for instance)
- Some bugs were fixed (especially the one that was sending the same packet 
	to all opened sockets).
- Auto close previous and remaining sockets (may happen when the daemon is 
	force-closed)
