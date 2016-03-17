# VNFManager

V3 Changelog : 
- Multithreading integration for a multiple socket capability.
- Catching all signals from the subprocess function that may disturbe
	the server-side shell when some programs are launched remotly (nano for instance)
- Some bugs were fixed (Especially the one that was sending the same packet 
	to all opened sockets).
- Auto close previous and remaining sockets (may happen when the daemon is 
	force-closed)
