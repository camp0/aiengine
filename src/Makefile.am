AUTOMAKE_OPTIONS = gnu

all: aiengine

python_PYTHON = pyai_tests.py __init__.py

# EXTRA_FLAGS = -flto not supported on the freebsd compiler
# EXTRA_FLAGS = -O3 '-fprofile-arcs -ftest-coverage -g' For enable gcov tool
EXTRA_FLAGS = -g -O0

EXTRA_DIST = python_wrapper.cc ruby_wrapper.i setup.py MANIFEST.in ruai_test.rb

noinst_HEADERS =        Packet.h Pointer.h RawPacket.h \
			Protocol.h AnomalyManager.h RejectManager.h \
			PacketDispatcher.h \
			NetworkStack.h \
			StackLan.h \
			StackLanIPv6.h \
			Cache.h CacheManager.h IPAddress.h \
			StackMobile.h StackVirtual.h \
			StackOpenFlow.h \
			Multiplexer.h \
			FlowForwarder.h \
			Signature.h Callback.h \
			Interpreter.h \
                        flow/FlowCache.h \
                        flow/FlowManager.h \
                        Flow.h StringCache.h \
			ipset/IPAbstractSet.h \
			ipset/IPBloomSet.h \
			ipset/IPSet.h \
			ipset/IPSetManager.h \
			learner/LearnerEngine.h \
			names/DomainName.h \
			names/DomainNode.h \
			names/DomainNameManager.h \
			protocols/ethernet/EthernetProtocol.h \
			protocols/vlan/VLanProtocol.h \
			protocols/mpls/MPLSProtocol.h \
			protocols/ip/IPProtocol.h \
			protocols/ip6/IPv6Protocol.h \
			protocols/icmp/ICMPProtocol.h \
			protocols/icmp6/ICMPv6Header.h \
			protocols/icmp6/ICMPv6Protocol.h \
			protocols/udp/UDPProtocol.h \
			protocols/tcp/TCPHeader.h \
			protocols/tcp/TCPProtocol.h \
			protocols/tcpgeneric/TCPGenericProtocol.h \
			protocols/udpgeneric/UDPGenericProtocol.h \
			protocols/gprs/GPRSProtocol.h \
			protocols/vxlan/VxLanProtocol.h \
			protocols/openflow/OpenFlowProtocol.h \
			protocols/gre/GREProtocol.h \
			protocols/http/HTTPProtocol.h \
			protocols/ssl/SSLProtocol.h \
			protocols/smtp/SMTPProtocol.h \
			protocols/imap/IMAPProtocol.h \
			protocols/pop/POPProtocol.h \
			protocols/dns/DNSProtocol.h \
			protocols/sip/SIPProtocol.h \
			protocols/dhcp/DHCPProtocol.h \
			protocols/ntp/NTPProtocol.h \
			protocols/snmp/SNMPProtocol.h \
			protocols/ssdp/SSDPProtocol.h \
			protocols/frequency/Frequencies.h \
			protocols/frequency/PacketFrequencies.h \
			protocols/frequency/FrequencyProtocol.h \
			System.h \
			StackLanTest.h \
			Serializable.h \
			DatabaseAdaptor.h 

aiengine_core_sources =	Multiplexer.cc \
			FlowForwarder.cc \
			PacketDispatcher.cc \
			Flow.cc CacheManager.cc \
			Protocol.cc AnomalyManager.cc \
			Callback.cc \
			Interpreter.cc \
			flow/FlowManager.cc \
			protocols/ethernet/EthernetProtocol.cc \
			protocols/vlan/VLanProtocol.cc \
			protocols/mpls/MPLSProtocol.cc \
			protocols/ip/IPProtocol.cc \
			ipset/IPSet.cc \
			ipset/IPBloomSet.cc \
			ipset/IPSetManager.cc \
			protocols/ip6/IPv6Protocol.cc \
			protocols/icmp/ICMPProtocol.cc \
			protocols/icmp6/ICMPv6Header.cc \
			protocols/icmp6/ICMPv6Protocol.cc \
			protocols/udp/UDPProtocol.cc \
			protocols/tcp/TCPHeader.cc \
			protocols/tcp/TCPProtocol.cc \
			protocols/tcpgeneric/TCPGenericProtocol.cc \
			protocols/udpgeneric/UDPGenericProtocol.cc \
			protocols/gprs/GPRSProtocol.cc \
			protocols/vxlan/VxLanProtocol.cc \
			protocols/openflow/OpenFlowProtocol.cc \
			protocols/gre/GREProtocol.cc \
			protocols/http/HTTPProtocol.cc \
			protocols/http/HTTPUriSet.cc \
			protocols/ssl/SSLProtocol.cc \
			protocols/smtp/SMTPProtocol.cc \
			protocols/imap/IMAPProtocol.cc \
			protocols/pop/POPProtocol.cc \
			protocols/dns/DNSProtocol.cc \
			protocols/sip/SIPProtocol.cc \
			protocols/dhcp/DHCPProtocol.cc \
			protocols/ntp/NTPProtocol.cc \
			protocols/snmp/SNMPProtocol.cc \
			protocols/ssdp/SSDPProtocol.cc \
			regex/Regex.cc \
			regex/RegexManager.cc RejectManager.cc \
			protocols/frequency/FrequencyProtocol.cc \
			protocols/frequency/FrequencyCounter.cc \
			learner/LearnerEngine.cc \
			names/DomainNameManager.cc \
			names/DomainName.cc \
			System.cc \
			NetworkStack.cc \
			StackMobile.cc StackLan.cc \
			StackLanIPv6.cc StackVirtual.cc \
			StackOpenFlow.cc 

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS = 
endif

BOOST_LINK_CORE = -lboost_system 

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
		protocols/ethernet/test_ethernet.cc \
		protocols/vlan/test_vlan.cc \
		protocols/mpls/test_mpls.cc \
		flow/test_flows.cc \
		ipset/test_ipset.cc \
		protocols/ip/test_ip.cc \
		protocols/ip6/test_ip6.cc \
		protocols/udp/test_udp.cc \
		protocols/tcp/test_tcp.cc \
		protocols/tcpgeneric/test_tcpgeneric.cc \
		protocols/udpgeneric/test_udpgeneric.cc \
		protocols/dns/test_dns.cc \
		protocols/gprs/test_gprs.cc \
		protocols/vxlan/test_vxlan.cc \
		protocols/openflow/test_openflow.cc \
		protocols/gre/test_gre.cc \
		protocols/http/test_http.cc \
		protocols/icmp/test_icmp.cc \
		protocols/icmp6/test_icmp6.cc \
		protocols/frequency/test_frequency.cc \
		protocols/ssl/test_ssl.cc \
		protocols/smtp/test_smtp.cc \
		protocols/imap/test_imap.cc \
		protocols/pop/test_pop.cc \
		protocols/sip/test_sip.cc \
		protocols/dhcp/test_dhcp.cc \
		protocols/ntp/test_ntp.cc \
		protocols/snmp/test_snmp.cc \
		protocols/ssdp/test_ssdp.cc \
		regex/test_regex.cc \
		user/test_users.cc \
		learner/test_learner.cc \
		names/test_names.cc \
		tests.cc 

tests_LDFLAGS = 	-DBOOST_ASIO_DISABLE_EPOLL -lpthread -lstdc++ \
			$(BOOST_LDFLAGS) $(BOOST_LINK_CORE) $(PCRE_LIB) \
			-lboost_program_options \
			-lboost_filesystem -lpcap $(LOG4CXX_FLAGS) 

ruby_objects = 	NetworkStack.o Protocol.o EthernetProtocol.o \
		AnomalyManager.o CacheManager.o Multiplexer.o FlowForwarder.o PacketDispatcher.o \
		Flow.o Callback.o \
		RegexManager.o Regex.o \
		VLanProtocol.o MPLSProtocol.o \
		IPProtocol.o IPv6Protocol.o TCPHeader.o TCPProtocol.o UDPProtocol.o \
		TCPGenericProtocol.o UDPGenericProtocol.o \
		HTTPProtocol.o SSLProtocol.o \
		DNSProtocol.o GPRSProtocol.o \
		NTPProtocol.o SNMPProtocol.o \
		SMTPProtocol.o IMAPProtocol.o \
		DHCPProtocol.o SIPProtocol.o SSDPProtocol.o \
		POPProtocol.o GREProtocol.o \
		OpenFlowProtocol.o VxLanProtocol.o \
		FrequencyProtocol.o LearnerEngine.o \
		ICMPProtocol.o ICMPv6Protocol.o ICMPv6Header.o \
		StackLan.o StackMobile.o StackLanIPv6.o StackVirtual.o StackOpenFlow.o \
		FlowManager.o Interpreter.o \
		IPSetManager.o IPSet.o HTTPUriSet.o \
		DomainNameManager.o DomainName.o RejectManager.o

tests_CPPFLAGS = $(BOOST_CPPFLAGS) -g 
# Dont forget to put -lgcov if need on test_LDADD
tests_LDADD   = $(BOOST_LIBS) $(BOOST_LINK_CORE) -lboost_unit_test_framework -lpcap -lpthread 

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

python:
	@echo "**************************************************************************************"
	@echo "* Depending on your machine this compilation could take some time, please be patient.*"
	@echo "* You can use alternatively the setup.py script (python setup.py build_ext -i).      *"
	@echo "**************************************************************************************"
	$(CXX) -g -O0 -fPIC $(EXTRA_FLAGS) -DHAVE_CONFIG_H -DPYTHON_BINDING \
		-I. -I.. $(BOOST_CPPFLAGS) $(BOOST_CPPFLAGS)/boost/python \
		`pkg-config --cflags python-$(PYTHON_VERSION)` \
		$(aiengine_core_sources) python_wrapper.cc \
		-std=c++11 -lpthread -lstdc++ \
		$(BOOST_LDFLAGS) $(BOOST_LINK_CORE) \
		-l$(BOOST_PYTHON_LIB) \
		`pkg-config --libs python-$(PYTHON_VERSION)` -lpcap \
		$(LOG4CXX_FLAGS) $(PCRE_LIB) -o pyaiengine.so -shared

ruby:
if HAVE_RUBY_SUPPORT
	@echo "**************************************************************************************"
	@echo "* Compiling Ruby extension.                                                          *"
	@echo "**************************************************************************************"
	@echo "Generating interface" $(SWIG)	
	swig -DRUBY_BINDING -globalmodule -c++ -ruby ruby_wrapper.i 	
	@echo "Compiling ruby interface"
	$(CXX) -fPIC $(EXTRA_FLAGS) -DHAVE_CONFIG_H -DRUBY_BINDING -I.. -I. \
		-std=c++11 -c $(aiengine_core_sources) ruby_wrapper_wrap.cxx \
		-I/usr/include/ruby -I/usr/local/lib/ruby/1.6/i686-linux 
	@echo "Linking ruby interface"
	$(CXX) -g -fPIC $(EXTRA_FLAGS) -DHAVE_CONFIG_H -DRUBY_BINDING -I.. \
		-shared -std=c++11 $(ruby_objects) ruby_wrapper_wrap.o -o ruaiengine.so -lpcap -lruby -lboost_system -lpcre
endif
