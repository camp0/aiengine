"""Example script for integrate/configureate the iaengine """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import os
import signal
import sys
import pyiaengine

def loadSignaturesForTcp():
	sm = pyiaengine.SignatureManager()
	
	sig = pyiaengine.Signature("^\x13BitTorrent")

	#sm.addSignature("^\x13BitTorrent")

	sm.addSignature(sig)

	return sm

def loadSignaturesForUdp():
	sm = pyiaengine.SignatureManager()

	sm.addSignature("^d1:ad2:id20")

	return sm

if __name__ == '__main__':

	#st = pyiaengine.Stack3G()
	st = pyiaengine.StackLan()

	pdis = pyiaengine.PacketDispatcher()

	pdis.setStack(st)
	s_tcp = loadSignaturesForTcp()
	st.setTCPSignatureManager(s_tcp)

	s_udp = loadSignaturesForUdp()
	st.setUDPSignatureManager(s_udp)
	
	st.setTotalTCPFlows(350000)
	st.setTotalUDPFlows(350000)

	directory = "/home/luis/pcapfiles/1"
	for pfile in os.listdir(directory):
		print "Processing ",pfile
		fpath = "%s/%s" %(directory,pfile)
		pdis.openPcapFile(fpath)

		try:
			pdis.runPcap()
		except:
			print "Error: capturing packets"
			pass

	f = open("pepe.dat",'w')
	s_tcp.statistics()
	s_udp.statistics()
	st.statistics(f)
	pdis.closePcapFile()

	sys.exit(0)

