AUTOMAKE_OPTIONS = gnu

EXTRA_DIST = py_wrapper.cc setup.py

noinst_HEADERS =        Packet.h \
			Protocol.h \
			PacketDispatcher.h \
			NetworkStack.h \
			StackLan.h \
			Cache.h \
			Stack3G.h \
			Multiplexer.h \
			FlowForwarder.h \
			./ethernet/EthernetProtocol.h \
			./vlan/VLanProtocol.h \
			./mpls/MPLSProtocol.h \
			./ip/IPProtocol.h \
			./icmp/ICMPProtocol.h \
			./udp/UDPProtocol.h \
			./tcp/TCPProtocol.h \
			./tcpgeneric/TCPGenericProtocol.h \
			./udpgeneric/UDPGenericProtocol.h \
			./gprs/GPRSProtocol.h \
			./http/HTTPProtocol.h \
			./ssl/SSLProtocol.h \
			./dns/DNSProtocol.h \
                        ./flow/FlowCache.h \
                        ./flow/FlowManager.h \
                        ./flow/Flow.h \
			./frequency/Frequencies.h \
			./frequency/FrequencyProtocol.h 

aiengine_core_sources =	Multiplexer.cc \
			FlowForwarder.cc \
			PacketDispatcher.cc \
			./flow/FlowManager.cc \
			./ethernet/EthernetProtocol.cc \
			./vlan/VLanProtocol.cc \
			./mpls/MPLSProtocol.cc \
			./ip/IPProtocol.cc \
			./icmp/ICMPProtocol.cc \
			./udp/UDPProtocol.cc \
			./tcp/TCPProtocol.cc \
			./tcpgeneric/TCPGenericProtocol.cc \
			./udpgeneric/UDPGenericProtocol.cc \
			./gprs/GPRSProtocol.cc \
			./http/HTTPProtocol.cc \
			./ssl/SSLProtocol.cc \
			./dns/DNSProtocol.cc \
			./signatures/Signature.cc \
			./signatures/SignatureManager.cc \
			./frequency/FrequencyProtocol.cc \
			Stack3G.cc StackLan.cc 

aiengine_SOURCES =      $(aiengine_core_sources) main.cc

aiengine_CPPFLAGS = $(BOOST_CPPFLAGS)
aiengine_LDFLAGS = -DBOOST_ASIO_DISABLE_EPOLL -lpthread -lstdc++ -lboost_system -lboost_thread -lboost_program_options -lboost_regex -lpcap
aiengine_LDADD = $(BOOST_LIBS)

bin_PROGRAMS = aiengine

TEST = tests 

check_PROGRAMS = tests 

tests_SOURCES = $(aiengine_core_sources) \
		./ethernet/test_ethernet.cc \
		./vlan/test_vlan.cc \
		./mpls/test_mpls.cc \
		./flow/test_flows.cc \
		./ip/test_ip.cc \
		./udp/test_udp.cc \
		./tcp/test_tcp.cc \
		./tcpgeneric/test_tcpgeneric.cc \
		./udpgeneric/test_udpgeneric.cc \
		./dns/test_dns.cc \
		./gprs/test_gprs.cc \
		./http/test_http.cc \
		./icmp/test_icmp.cc \
		./frequency/test_frequency.cc \
		./signatures/test_signatures.cc \
		./ssl/test_ssl.cc \
		./user/test_users.cc \
		tests.cc 

tests_LDADD   = -lboost_system -lboost_unit_test_framework -lboost_regex -lpcap
tests_LDFLAGS = -DBOOST_ASIO_DISABLE_EPOLL

BUILT_SOURCES = $(srcdir)/pyaiengine.so

$(srcdir)/pyaiengine.so: py_wrapper.cc
	g++ -fPIC $(aiengine_core_sources) \
        	py_wrapper.cc `pkg-config --cflags python-2.7` \
		-I/usr/include/boost/python -std=c++11 -lpthread -lstdc++ -lboost_system \
		-lboost_thread -lboost_regex -lboost_python -lpython2.7 -lpcap -o pyaiengine.so -shared

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

