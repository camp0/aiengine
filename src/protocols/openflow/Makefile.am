AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_openflow.h

TEST = test_openflow

check_PROGRAMS = test_openflow

test_openflow_SOURCES =	../../Multiplexer.cc ../../Protocol.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			../udpgeneric/UDPGenericProtocol.cc \
			../tcpgeneric/TCPGenericProtocol.cc \
			../tcp/TCPProtocol.cc \
			../../regex/RegexManager.cc \
			../../regex/Regex.cc \
			../../names/DomainNameManager.cc \
			../dns/DNSProtocol.cc \
			../icmp/ICMPProtocol.cc \
			OpenFlowProtocol.cc test_openflow.cc

test_openflow_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_openflow_LDADD   = $(BOOST_LDFLAGS) $(PCRE_LIB) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

