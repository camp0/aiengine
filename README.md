AIEngine (Artificial Inteligent Engine)
=========

AIEngine is a packet inspection engine with capabilities of learning
without any human intervention.  

AIEngine helps network/security profesionals to identify traffic and develop
signatures for use them on NIDS, Firewalls, Traffic classifiers and so on.

The main functionalities of AIEngine are:

- Support for PCRE JIT for regex matching.
- Support three types of NetworkStacks(lan,mobile and ipv6)
- Support Sets and Bloom filters for IP searches.
- Support Linux and FreeBSD operating systems.
- Support for HTTP,DNS and SSL Domains matching.
- Support for banned domains and hosts for HTTP, DNS and SSL
- Frequency analisys for unknown traffic and auto-regex generation.
- Easy integration with databases (MySQL, Redis, etc...)

Using AIEngine 
---------------

To use AIEngine just execute the binary aiengine or use the python binding.

	luis@luis-xps:~/c++/aiengine/src$ ./aiengine -h
	aiengine 0.8
	Mandatory arguments:
	  -I [ --interface ] arg            Sets the network interface.
	  -P [ --pcapfile ] arg             Sets the pcap file or directory with pcap 
                                    	    files.

	Link Layer optional arguments:
	  -q [ --tag ] arg      Selects the tag type of the ethernet layer (vlan,mpls).

	TCP optional arguments:
	  -t [ --tcp-flows ] arg (=32768) Sets the number of TCP flows on the pool.

	UDP optional arguments:
	  -u [ --udp-flows ] arg (=16384) Sets the number of UDP flows on the pool.

	Regex optional arguments:
	  -R [ --enable-signatures ]     Enables the Signature engine.
	  -r [ --regex ] arg (=.*)       Sets the regex for evaluate agains the flows.
	  -c [ --flow-class ] arg (=all) Uses tcp, udp or all for matches the signature
					 on the flows.

	Frequencies optional arguments:
	  -F [ --enable-frequencies ]       Enables the Frequency engine.
	  -g [ --group-by ] arg (=dst-port) Groups frequencies by src-ip,dst-ip,src-por
					    t and dst-port.
	  -f [ --flow-type ] arg (=tcp)     Uses tcp or udp flows.
	  -L [ --enable-learner ]           Enables the Learner engine.
	  -k [ --key-learner ] arg (=80)    Sets the key for the Learner engine.

	Optional arguments:
	  -n [ --stack ] arg (=lan)    Sets the network stack (lan,mobile,lan6).
	  -d [ --dumpflows ]           Dump the flows to stdout.
	  -s [ --statistics ] arg (=0) Show statistics of the network stack (5 levels).
	  -p [ --pstatistics ]         Show statistics of the process.
	  -h [ --help ]                Show help.
	  -v [ --version ]             Show version string.

Integrating AIEngine with other systems 
---------------------------------------

AIEngine have a python module in order to be more flexible in terms of integration with other systems and functionalities.
The main objects that the python module provide are the following ones.

	DNSDomain
	DatabaseAdaptor
	   |---> connect
	   |---> insert
	   |---> remove
	   |---> update
	DomainName
	   |---> getExpression
	   |---> getMatchs
	   |---> getName
	   |---> setCallback
	DomainNameManager
	   |---> addDomainName
	   |---> getTotalDomains
	Flow
	   |---> getDNSDomain
	   |---> getDestinationAddress
	   |---> getDestinationPort
	   |---> getFrequencies
	   |---> getHTTPHost
	   |---> getHTTPUserAgent
	   |---> getIPSet
	   |---> getPacketFrequencies
	   |---> getPayload
	   |---> getProtocol
	   |---> getRegex
	   |---> getSSLHost
	   |---> getSourceAddress
	   |---> getSourcePort
	   |---> getTotalBytes
	   |---> getTotalPackets
	   |---> getTotalPacketsLayer7
	FlowManager
	   |---> getTotalFlows
	Frequencies
	   |---> getDispersion
	   |---> getEnthropy
	   |---> getFrequenciesString
	HTTPHost
	HTTPUserAgent
	IPSet
	   |---> addIPAddress
	   |---> getTotalIPs
	   |---> setCallback
	IPSetManager
	   |---> addIPSet
	   |---> getTotalSets
	LearnerEngine
	   |---> agregateFlows
	   |---> compute
	   |---> getRegularExpression
	   |---> getTotalFlowsProcess
	NetworkStack
	   |---> enableFrequencyEngine
	   |---> enableLinkLayerTagging
	   |---> enableNIDSEngine
	   |---> getTCPFlowManager
	   |---> getUDPFlowManager
	   |---> printFlows
	   |---> setDNSDomainNameManager
	   |---> setHTTPHostNameManager
	   |---> setSSLHostNameManager
	   |---> setStatisticsLevel
	   |---> setTCPDatabaseAdaptor
	   |---> setTCPIPSetManager
	   |---> setTCPRegexManager
	   |---> setTotalTCPFlows
	   |---> setTotalUDPFlows
	   |---> setUDPDatabaseAdaptor
	   |---> setUDPIPSetManager
	   |---> setUDPRegexManager
	PacketDispatcher
	   |---> closeDevice
	   |---> closePcapFile
	   |---> openDevice
	   |---> openPcapFile
	   |---> runDevice
	   |---> runPcap
	   |---> setStack
	PacketFrequencies
	   |---> getPacketFrequenciesString
	Regex
	   |---> getExpression
	   |---> getMatchs
	   |---> getName
	   |---> setCallback
	   |---> setNextRegex
	RegexManager
	   |---> addRegex
	SSLHost
	StackLan
	   |---> enableFrequencyEngine
	   |---> enableLinkLayerTagging
	   |---> enableNIDSEngine
	   |---> getTCPFlowManager
	   |---> getUDPFlowManager
	   |---> printFlows
	   |---> setDNSDomainNameManager
	   |---> setHTTPHostNameManager
	   |---> setSSLHostNameManager
	   |---> setStatisticsLevel
	   |---> setTCPDatabaseAdaptor
	   |---> setTCPIPSetManager
	   |---> setTCPRegexManager
	   |---> setTotalTCPFlows
	   |---> setTotalUDPFlows
	   |---> setUDPDatabaseAdaptor
	   |---> setUDPIPSetManager
	   |---> setUDPRegexManager
	StackLanIPv6
	   |---> enableFrequencyEngine
	   |---> enableLinkLayerTagging
	   |---> enableNIDSEngine
	   |---> getTCPFlowManager
	   |---> getUDPFlowManager
	   |---> printFlows
	   |---> setDNSDomainNameManager
	   |---> setHTTPHostNameManager
	   |---> setSSLHostNameManager
	   |---> setStatisticsLevel
	   |---> setTCPDatabaseAdaptor
	   |---> setTCPIPSetManager
	   |---> setTCPRegexManager
	   |---> setTotalTCPFlows
	   |---> setTotalUDPFlows
	   |---> setUDPDatabaseAdaptor
	   |---> setUDPIPSetManager
	   |---> setUDPRegexManager
	StackMobile
	   |---> enableFrequencyEngine
	   |---> enableLinkLayerTagging
	   |---> enableNIDSEngine
	   |---> getTCPFlowManager
	   |---> getUDPFlowManager
	   |---> printFlows
	   |---> setDNSDomainNameManager
	   |---> setHTTPHostNameManager
	   |---> setSSLHostNameManager
	   |---> setStatisticsLevel
	   |---> setTCPDatabaseAdaptor
	   |---> setTCPIPSetManager
	   |---> setTCPRegexManager
	   |---> setTotalTCPFlows
	   |---> setTotalUDPFlows
	   |---> setUDPDatabaseAdaptor
	   |---> setUDPIPSetManager
	   |---> setUDPRegexManager
	std_ostream

Check the configuration wiki pages in order to have more complex examples.
[https://bitbucket.org/camp0/aiengine/wiki/Configurations Configurations]

Compile AIEngine
----------------

    $ git clone https://bitbucket.com/camp0/aiengine
    $ ./autogen.sh
    $ ./configure
    $ make

Contributing to AIEngine 
-------------------------

AIEngine is under the terms of GPLv2 and is under develop.

Check out the AIEngine source with 

    $ git clone https://bitbucket.com/camp0/aiengine

For make donations use the following bitcoin address

    1MieEN8eX8PcPvwgwQnVjzxJ1U8DTogZzb

Develop new functionality
-------------------------

AIEngine have been develop using test driven development. So in order to maintain the same life cicle, the new functionatly
 should have unit test on the directory created of the new functionality and for integrate with all the system, later integrate
with the main tests.cc file on the /src directory

