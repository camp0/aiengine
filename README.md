AIEngine (Artificial Inteligent Engine)
=========

AIEngine is a packet inspection engine with capabilities of learning
without any human intervention.  

AIEngine helps network/security profesionals to identify traffic and develop
signatures for use them on NIDS, Firewalls, Traffic classifiers and so on.

Using AIEngine 
---------------

To use AIEngine just execute the binary aiengine:

	luis@luis-xps:~/c++/aiengine/src$ ./aiengine -h
	iaengine 0.1
	Mandatory arguments:
	  -i [ --interface ] arg            Sets the network interface.
	  -f [ --pcapfile ] arg             Sets the pcap file.

	TCP optional arguments:
	  -t [ --tcp-flows ] arg (=32768) Sets the number of TCP flows on the pool.

	UDP optional arguments:
	  -u [ --udp-flows ] arg (=16384) Sets the number of UDP flows on the pool.

	Frequencies optional arguments:
	  -F [ --enable-frequencies ]       Enables the Frequency engine.
	  -g [ --group-by ] arg (=dst-port) Groups frequencies by src-ip,dst-ip,src-por
					    t and dst-port.
	  -T [ --flow-type ] arg (=tcp)     Uses tcp or udp flows.
	  -L [ --enable-learner ]           Enables the Learner engine.
	  -k [ --key-learner ] arg (=80)    Sets the key for the Learner engine.

	Optional arguments:
	  -S [ --stack ] arg (=lan)    Sets the network stack (lan,mobile).
	  -d [ --dumpflows ]           Dump the flows to stdout.
	  -s [ --statistics ] arg (=0) Show statistics of the network stack.
  	  -p [ --pstatistics ]         Show statistics of the process.
  	  -h [ --help ]                Show help.
  	  -v [ --version ]             Show version string.
 

Compile AIEngine
----------------

    $ git clone git://bitbucket.com/camp0/aiengine
    $ ./autogen.sh
    $ ./configure
    $ make

Contributing to AIEngine 
-------------------------

AIEngine is under the terms of GPLv2 and is under develop.

Check out the AIEngine source with 

    $ git clone git://bitbucket.com/camp0/aiengine

