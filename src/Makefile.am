AUTOMAKE_OPTIONS = gnu

python_PYTHON = pyai.py

# EXTRA_FLAGS = -flto not supported on the freebsd compiler
EXTRA_FLAGS = 
EXTRA_DIST = py_wrapper.cc setup.py

noinst_HEADERS =        Packet.h Pointer.h \
			Protocol.h \
			PacketDispatcher.h \
			NetworkStack.h \
			StackLan.h \
			StackLanIPv6.h \
			Cache.h IPAddress.h \
			StackMobile.h \
			Multiplexer.h \
			FlowForwarder.h \
			Signature.h \
			./ethernet/EthernetProtocol.h \
			./vlan/VLanProtocol.h \
			./mpls/MPLSProtocol.h \
			./ip/IPProtocol.h \
			./ip6/IPv6Protocol.h \
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
			./frequency/PacketFrequencies.h \
			./frequency/FrequencyProtocol.h \
			./learner/LearnerEngine.h \
			./names/DomainName.h \
			./names/DomainNode.h \
			./names/DomainNameManager.h \
			System.h StackLanTest.h 

aiengine_core_sources =	Multiplexer.cc \
			FlowForwarder.cc \
			PacketDispatcher.cc \
			./flow/FlowManager.cc \
			./ethernet/EthernetProtocol.cc \
			./vlan/VLanProtocol.cc \
			./mpls/MPLSProtocol.cc \
			./ip/IPProtocol.cc \
			./ip6/IPv6Protocol.cc \
			./icmp/ICMPProtocol.cc \
			./udp/UDPProtocol.cc \
			./tcp/TCPProtocol.cc \
			./tcpgeneric/TCPGenericProtocol.cc \
			./udpgeneric/UDPGenericProtocol.cc \
			./gprs/GPRSProtocol.cc \
			./http/HTTPProtocol.cc \
			./ssl/SSLProtocol.cc \
			./dns/DNSProtocol.cc \
			./regex/Regex.cc \
			./regex/RegexManager.cc \
			./frequency/FrequencyProtocol.cc \
			./frequency/FrequencyCounter.cc \
			./learner/LearnerEngine.cc \
			./names/DomainNameManager.cc \
			System.cc \
			StackMobile.cc StackLan.cc \
			StackLanIPv6.cc  

if SUPPORT_LOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS = 
endif

BOOST_LINK_CORE = -lboost_system -lboost_thread -lboost_regex

aiengine_SOURCES =      $(aiengine_core_sources) main.cc
aiengine_CPPFLAGS = 	$(EXTRA_FLAGS) $(BOOST_CPPFLAGS)
aiengine_LDFLAGS = 	-DBOOST_ASIO_DISABLE_EPOLL -lpthread -lstdc++ \
			$(BOOST_LDFLAGS) $(BOOST_LINK_CORE) $(PCRE_LIB) \
			-lboost_program_options \
			-lboost_filesystem -lpcap $(LOG4CXX_FLAGS) 

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
		./ip6/test_ip6.cc \
		./udp/test_udp.cc \
		./tcp/test_tcp.cc \
		./tcpgeneric/test_tcpgeneric.cc \
		./udpgeneric/test_udpgeneric.cc \
		./dns/test_dns.cc \
		./gprs/test_gprs.cc \
		./http/test_http.cc \
		./icmp/test_icmp.cc \
		./frequency/test_frequency.cc \
		./regex/test_regex.cc \
		./ssl/test_ssl.cc \
		./user/test_users.cc \
		./learner/test_learner.cc \
		./names/test_names.cc \
		tests.cc 

tests_LDFLAGS = 	-DBOOST_ASIO_DISABLE_EPOLL -lpthread -lstdc++ \
			$(BOOST_LDFLAGS) $(BOOST_LINK_CORE) $(PCRE_LIB) \
			-lboost_program_options \
			-lboost_filesystem -lpcap $(LOG4CXX_FLAGS) 

tests_CPPFLAGS = $(BOOST_CPPFLAGS)
tests_LDADD   = $(BOOST_LIBS) $(BOOST_LINK_CORE) -lboost_unit_test_framework -lpcap -lpthread

BUILT_SOURCES = $(srcdir)/pyaiengine.so

$(srcdir)/pyaiengine.so: py_wrapper.cc
	$(CXX) -fPIC $(EXTRA_FLAGS) -DHAVE_CONFIG_H -DPYTHON_BINDING \
		-I. -I.. $(BOOST_CPPFLAGS) $(BOOST_CPPFLAGS)/boost/python \
		`pkg-config --cflags python-2.7` \
		$(aiengine_core_sources) py_wrapper.cc \
		-std=c++11 -lpthread -lstdc++ \
		$(BOOST_LDFLAGS) $(BOOST_LINK_CORE) -lboost_python -lpython2.7 -lpcap \
		$(LOG4CXX_FLAGS) $(PCRE_LIB) -o pyaiengine.so -shared

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

