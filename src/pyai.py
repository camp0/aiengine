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



def processFlows(flowlist):

        print "number of flows:", len(flowlist)
        for flow in flowlist:
                name = str(flow)
                print name,flow.getTotalBytes() #,flow.getSourcePort(),flow.getDestinationPort()

                if(flow.getHTTPHost()):
			print "tiene"
                        print flow.getHTTPHost()

                if(flow.getHTTPUserAgent()):
                        print flow.getHTTPUserAgent()

		if(flow.getFrequencies()):
			freq = flow.getFrequencies()
			print freq.getFrequenciesString()

		if(flow.getPacketFrequencies()):
			freq_pkt = flow.getPacketFrequencies()
			print freq_pkt.getPacketFrequenciesString()


if __name__ == '__main__':

	st = pyaiengine.StackMobile()
	#st = pyaiengine.StackLan()

	pdis = pyaiengine.PacketDispatcher()

	pdis.setStack(st)
	
	s_tcp = loadSignaturesForTcp()
	st.setTCPSignatureManager(s_tcp)

	s_udp = loadSignaturesForUdp()
	st.setUDPSignatureManager(s_udp)
	
	st.setTotalTCPFlows(32768)
	st.setTotalUDPFlows(16384)

	#st.enableFrequencyEngine(True)
	st.enableLinkLayerTagging("vlan")

	directory = "/home/luis/pcapfiles/torrent/vuze"
	directory = "/home/luis/pcapfiles/defcon18/"
	directory = "/home/luis/pcapfiles/http/"
	#directory = "/home/luis/pcapfiles/vcom/"
	directory = "/home/luis/pcapfiles/spotify/1/"
	print "Ready to process files."
	for pfile in os.listdir(directory):
		print "Processing ",pfile
		fpath = "%s/%s" %(directory,pfile)
		pdis.openPcapFile(fpath)

		try:
			pdis.runPcap()
		except:
			print "Error: capturing packets"
			break	

	flows = st.getTCPFlowManager()

	processFlows(flows)

	f = open("signatures_tcp.log","w")
	f.write(str(s_tcp))
	f.close()

	f = open("statistics.log","w")
	f.write(str(st))
	f.close()

	#st.printFlows()

	pdis.closePcapFile()

	sys.exit(0)

