AIEngine (Artificial Inteligent Engine)
=========

AIEngine is a next generation interactive/programmable packet inspection engine with capabilities of learning
without any human intervention and other functionalities such as NIDS functionality, 
domain classification, network collector and many others.  

AIEngine helps network/security profesionals to identify traffic and develop
signatures for use them on NIDS, Firewalls, Traffic classifiers and so on.

The main functionalities of AIEngine are:

- Support for interact with the user while the engine is running.
- Support for PCRE JIT for regex matching.
- Support for regex graphs.
- Support four types of NetworkStacks (lan,mobile, ipv6 and virtual).
- Support Sets and Bloom filters for IP searches.
- Support Linux and FreeBSD operating systems.
- Support for HTTP,DNS and SSL Domains matching.
- Support for banned domains and hosts for HTTP, DNS and SSL.
- Frequency analisys for unknown traffic and auto-regex generation.
- Easy integration with databases (MySQL, Redis, etc...) for data correlation.
- Easy integration with other packet engines (Netfilter).
- Support memory clean caches for refresh stored memory information.

Using AIEngine 
---------------

To use AIEngine just execute the binary aiengine or use the python binding.

	luis@luis-xps:~/c++/aiengine/src$ ./aiengine -h
	aiengine 0.10
	Mandatory arguments:
	  -I [ --input ] arg                Sets the network interface ,pcap file or 
	                                    directory with pcap files.

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
	  -n [ --stack ] arg (=lan)    Sets the network stack (lan,mobile,lan6,virtual).
	  -d [ --dumpflows ]           Dump the flows to stdout.
	  -s [ --statistics ] arg (=0) Show statistics of the network stack (5 levels).
          -T [ --timeout ] arg (=180)  Sets the flows timeout.
          -P [ --protocol ] arg        Show statistics of a specific protocol of the 
                                       network stack.
          -e [ --release ]             Release the caches.
          -l [ --release-cache ] arg   Release a specific cache.
	  -p [ --pstatistics ]         Show statistics of the process.
	  -h [ --help ]                Show help.
	  -v [ --version ]             Show version string.

NetworkStack types
---------------
AIEngine supports four types of Network stacks depending on the network topology.

- StackLan (lan) Local Area Network based on IPv4.

- StackLanIPv6 (lan6) Local Area Network with IPv6 support.

- StackMobile (mobile) Network Mobile (Gn interface) for IPv4.

- StackVirtual (virtual) Stack for virtual/cloud environments with VxLan and GRE Transparent.

Integrating AIEngine with other systems 
---------------------------------------

AIEngine have a python module in order to be more flexible in terms of integration with other systems and functionalities.
The main objects that the python module provide are the following ones.

        DNSDomain
        DatabaseAdaptor (Abstract class)
        DomainName
        DomainNameManager
        Flow
        FlowManager
        Frequencies
        FrequencyGroup
        HTTPHost
        HTTPUri
        HTTPUserAgent
        IPAbstractSet (Abstract class)
            IPSet
        IPSetManager
        LearnerEngine
        NetworkStack (Abstract class)
            StackLan
            StackLanIPv6
            StackMobile
            StackVirtual
        PacketDispatcher
        PacketFrequencies
        Regex
        RegexManager
        SSLHost

For a complete description of the class methods 

	import pyaiengine
	help(pyaiengine)

Check the configuration wiki pages or the examples directory in order to have more complex examples.
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