"""Example script for integrate/configureate the iaengine """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"

import signal
import sys
import pyiaengine

def loadSignaturesForTcp():
	sm = pyiaengine.SignatureManager()
	
#	sig = pyiaengine.Signature("^\x13BitTorrent")

	sm.addSignature("^\x13BitTorrent")

	return sm

if __name__ == '__main__':

	st = pyiaengine.StackLan()

	pdis = pyiaengine.PacketDispatcher()

	pdis.setStack(st)

	pdis.openPcapFile("/home/luis/pcapfiles/2012112216pcap_dump_40100000.pcap.pcap")

	s =loadSignaturesForTcp()

	#st.setTCPSignatureManager(s)

	try:
		pdis.runPcap()
	except:
		print "Error: capturing packets"
		pass

	st.statistics()
	pdis.closePcapFile()

	sys.exit(0)

