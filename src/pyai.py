"""Example script for integrate/configurate the aiengine """
__author__ = "Luis Campo Giralte"
__copyright__ = "Copyright (C) 2013 by Luis Campo Giralte"
__revision__ = "$Id$"
__version__ = "0.1"
import os
import signal
import sys
import pyaiengine

def callback_drop_packets(flow_name):

	print "hola", str(flow_name).split(":")[0]

#	sys.system("iptables -A INPUT -i eth0 -s %s -j DROP" % source_ip)


def loadRegexForTcp():
	sm = pyaiengine.RegexManager()
	
	reg = pyaiengine.Regex("Shellcode Generic Exploit","\x90\x90\x90\x90\x90\x90\x90\x90\x90")

	reg.setCallback(callback_drop_packets)
	sm.addRegex(reg)

	return sm

def loadRegexForUdp():
	sm = pyaiengine.RegexManager()

	reg = pyaiengine.Regex("bittorrent udp","^d1:ad2:id20");
	reg.setCallback(callback_drop_packets)
	
	sm.addRegex(reg)

	return sm



def processFlows(flowlist):
	"""
	This function gets all the flows of the flowlist
	and process according to your need
	"""
	
	candidate = list()

        print "Total flows:", len(flowlist)
        for flow in flowlist:

		if(flow.getTotalBytes() > 0):
			name = str(flow)
			print name,flow.getTotalBytes() #,flow.getSourcePort(),flow.getDestinationPort()

			if(flow.getHTTPHost()):
				print flow.getHTTPHost()

			if(flow.getHTTPUserAgent()):
				print flow.getHTTPUserAgent()

			if(flow.getFrequencies()):
				freq = flow.getFrequencies()
				print "Enthropy:", freq.getEnthropy()
				#print freq.getFrequenciesString()

			if(flow.getPacketFrequencies()):
				freq_pkt = flow.getPacketFrequencies()
				#print freq_pkt.getPacketFrequenciesString()

			if(flow.getDestinationPort() == 2525):	
				candidate.append(flow)

	""" Extract a valid signature for the flows of the list """
	learner = pyaiengine.LearnerEngine()

	learner.agregateFlows(candidate)
	learner.compute()

	print "Learning flows", learner.getTotalFlowsProcess()
	regex = learner.getRegularExpression()
	print "Regex:",regex
	

if __name__ == '__main__':

	# Load an instance of a Network Stack
	#st = pyaiengine.StackMobile()
	st = pyaiengine.StackLan()

	# Create a instace of a PacketDispatcher 
	pdis = pyaiengine.PacketDispatcher()

	# Plug the stack on the PacketDispatcher
	pdis.setStack(st)

	# Load Signatures/Rules in order to detect the traffic
	# Use OpenDPI rules, Snort, L7Filter, etc...
	#	
	s_tcp = loadRegexForTcp()
	st.setTCPRegexManager(s_tcp)

	s_udp = loadRegexForUdp()
	st.setUDPRegexManager(s_udp)

	# Allocate the TCP/UDP flows in order to keep memory
	# under control and avoid allocations during the execution	
	st.setTotalTCPFlows(327680)
	st.setTotalUDPFlows(163840)

	print "memory allocated"
	# Enable FrequencyEngine if want to extract signatures from the flows
	# st.enableFrequencyEngine(True)

	# Enable VLAN tag if needed or MPLS
	# st.enableLinkLayerTagging("vlan")

	directory = "/home/luis/pcapfiles/torrent/transmission/"
	#directory = "/home/luis/pcapfiles/defcon18/"
	#directory = "/home/luis/pcapfiles/http/"
	#directory = "/home/luis/pcapfiles/vcom/"
	#directory = "/home/luis/pcapfiles/spotify/"
	print "Ready to process files."
	for pfile in os.listdir(directory):
		print "Processing ",pfile
		fpath = "%s/%s" %(directory,pfile)
		pdis.openPcapFile(fpath)

		try:
			pdis.runPcap()
		except:
			e = sys.exc_info()[0]
			print "Error: capturing packets:",e
			break	

	# Get the TCP or UDP flows processed
	flows = st.getTCPFlowManager()

	# Do the work, analize, inspect, resolve DNS, etc...
	processFlows(flows)

	# Dump on files all the statistics of the TCP Signatures
	f = open("signatures_tcp.log","w")
	f.write(str(s_tcp))
	f.close()

	# Dump on file the statistics of the stack
	st.setStatisticsLevel(5)
	f = open("statistics.log","w")
	f.write(str(st))
	f.close()

	# Print flows 
	#st.printFlows()

	# Close the PacketDispatcher
	pdis.closePcapFile()

	sys.exit(0)

