AIEngine (Artificial Inteligent Engine)
=========

AIEngine is a next generation interactive/programmable Python/Ruby/Java packet inspection engine with capabilities of learning
without any human intervention, NIDS(Network Intrusion Detection System) functionality, DNS domain classification, network collector, network forensics and many others. 

AIEngine also helps network/security professionals to identify traffic and develop
signatures for use them on NIDS, Firewalls, Traffic classifiers and so on.

The main functionalities of AIEngine are:

- Support for interacting/programing with the user while the engine is running.
- Support for PCRE JIT for regex matching.
- Support for regex graphs.
- Support five types of NetworkStacks (lan,mobile,lan6,virtual and oflow).
- Support Sets and Bloom filters for IP searches.
- Support Linux, FreeBSD and MacOS operating systems.
- Support for HTTP,DNS and SSL Domains matching.
- Support for banned domains and hosts for HTTP, DNS, SMTP and SSL.
- Frequency analysis for unknown traffic and auto-regex generation.
- Generation of Yara signatures.
- Easy integration with databases (MySQL, Redis, Cassandra, Hadoop, etc...) for data correlation.
- Easy integration with other packet engines (Netfilter).
- Support memory clean caches for refresh stored memory information.
- Support for detect DDoS at network/application layer.
- Support for rejecting TCP/UDP connections.
- Support for network forensics on real time.

Using AIEngine 
---------------

To use AIEngine(reduce version) just execute the binary aiengine or use the python/ruby/java binding.

	luis@luis-xps:~/c++/aiengine/src$ ./aiengine -h
	aiengine 1.4
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
	  -m [ --matched-flows ]         Shows the flows that matchs with the regex.
	  -j [ --reject-flows ]          Rejects the flows that matchs with the 
                                         regex.
	  -w [ --evidence ]              Generates a pcap file with the matching 
                                         regex for forensic analysis.

	Frequencies optional arguments:
	  -F [ --enable-frequencies ]       Enables the Frequency engine.
	  -g [ --group-by ] arg (=dst-port) Groups frequencies by src-ip,dst-ip,src-por
					    t and dst-port.
	  -f [ --flow-type ] arg (=tcp)     Uses tcp or udp flows.
	  -L [ --enable-learner ]           Enables the Learner engine.
	  -k [ --key-learner ] arg (=80)    Sets the key for the Learner engine.
	  -b [ --buffer-size ] arg (=64)    Sets the size of the internal buffer for 
        	                            generate the regex.
	  -y [ --enable-yara ]              Generates a yara signature.

	Optional arguments:
	  -n [ --stack ] arg (=lan)    Sets the network stack (lan,mobile,lan6,virtual,
				       oflow).
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
AIEngine supports five types of Network stacks depending on the network topology.

- StackLan (lan) Local Area Network based on IPv4.

- StackLanIPv6 (lan6) Local Area Network with IPv6 support.

- StackMobile (mobile) Network Mobile (Gn interface) for IPv4.

- StackVirtual (virtual) Stack for virtual/cloud environments with VxLan and GRE Transparent.

- StackOpenFlow (oflow) Stack for openflow environments.

Integrating/Program AIEngine with other systems 
------------------------------------------------

AIEngine is a python/ruby/java module also that allows to be more flexible in terms of integration with other systems and functionalities.
The main objects that the python module provide export are the following ones.

        DNSInfo
        DatabaseAdaptor (Abstract class)
        DomainName
        DomainNameManager
        Flow
        FlowManager
        Frequencies
        FrequencyGroup
        HTTPInfo
        HTTPUriSet
        IMAPInfo
        IPAbstractSet (Abstract class)
            IPSet
        IPSetManager
        LearnerEngine
        NetworkStack (Abstract class)
            StackLan
            StackLanIPv6
            StackMobile
            StackOpenFlow
            StackVirtual
        POPInfo
        PacketDispatcher
        PacketFrequencies
        Regex
        RegexManager
        SIPInfo
        SMTPInfo
        SSLInfo

For a complete description of the class methods 

	import pyaiengine
	help(pyaiengine)

Check the configuration wiki pages or the examples directory in order to have more complex examples.
[https://bitbucket.org/camp0/aiengine/wiki/Configurations Configurations]

Compile AIEngine binary
-----------------------

    $ git clone https://bitbucket.com/camp0/aiengine
    $ ./autogen.sh
    $ ./configure
    $ make

Compile AIEngine Python library
--------------------------------

The first option for compile the library is using O3 compile optimization, this will generate a small library

    $ git clone https://bitbucket.com/camp0/aiengine
    $ ./autogen.sh
    $ ./configure
    $ cd src
    $ make python

The second option will compile the library by using the standard pythonic way by using setup.py, this will generate
a bigger library size if compare with the previous one.

    $ git clone https://bitbucket.com/camp0/aiengine
    $ ./autogen.sh
    $ ./configure
    $ cd src
    $ python setup.py build_ext -i 
   
Compile AIEngine Ruby library 
------------------------------

The ruby library is still on develop phase.

    $ git clone https://bitbucket.com/camp0/aiengine
    $ ./autogen.sh
    $ ./configure
    $ cd src
    $ make ruby

Compile AIEngine Java library
------------------------------

The java library is still on develop phase.

    $ git clone https://bitbucket.com/camp0/aiengine
    $ ./autogen.sh
    $ ./configure
    $ cd src
    $ make java
    $ java -cp ".:/usr/share/java/junit.jar:/usr/share/java/hamcrest/core.jar:./buildjava" org.junit.runner.JUnitCore JunitTestSuite

Contributing to AIEngine 
-------------------------

AIEngine is develop with c++11/14 standard and is under the terms of GPLv2.

Check out the AIEngine source with 

    $ git clone https://bitbucket.com/camp0/aiengine

Develop new functionality
-------------------------

AIEngine have been develop using test driven development. So in order to maintain the same life cicle, the new functionatly
 should have unit test on the directory created of the new functionality and for integrate with all the system, later integrate
with the main tests.cc file on the /src directory
