"""Example script for integrate/configurate the aiengine """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import os
import signal
import sys
import pyaiengine

def loadSignaturesForTcp():
	sm = pyaiengine.SignatureManager()
	
	sig = pyaiengine.Signature("bittorrent tcp","^\x13BitTorrent")

	sm.addSignature(sig)

	return sm

def loadSignaturesForUdp():
	sm = pyaiengine.SignatureManager()

	sm.addSignature("bittorrent udp","^d1:ad2:id20")

	return sm

if __name__ == '__main__':

#	st = pyaiengine.StackMobile()
	st = pyaiengine.StackLan()

	pdis = pyaiengine.PacketDispatcher()

	pdis.setStack(st)
	
	s_tcp = loadSignaturesForTcp()
	st.setTCPSignatureManager(s_tcp)

	s_udp = loadSignaturesForUdp()
	st.setUDPSignatureManager(s_udp)
	
	st.setTotalTCPFlows(32768)
	st.setTotalUDPFlows(16384)

	st.enableFrequencyEngine(True)

	directory = "/home/luis/pcapfiles/torrent/vuze"
	directory = "/home/luis/pcapfiles/defcon18/"
	directory = "/home/luis/pcapfiles/http/"
#	directory = "/home/luis/pcapfiles/vcom/"
	print "Ready to process files."
	for pfile in os.listdir(directory):
		print "Processing ",pfile
		fpath = "%s/%s" %(directory,pfile)
		pdis.openPcapFile(fpath)

		try:
			pdis.runPcap()
		except:
			print "Error: capturing packets"
			pass

	
	flows = st.getTCPFlowManager()

#	print "number of flows:", len(flows)
	for flow in flows:
		print flow

	f = open("signatures_tcp.log","w")
	f.write(str(s_tcp))
	f.close()

	f = open("statistics.log","w")
	f.write(str(st))
	f.close()

	st.printFlows()

	pdis.closePcapFile()

	sys.exit(0)

