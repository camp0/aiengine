AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

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
			../gprs/GPRSInfo.cc \
			../dns/DNSInfo.cc \
			../sip/SIPInfo.cc \
			../udpgeneric/UDPGenericProtocol.cc \
			../tcpgeneric/TCPGenericProtocol.cc \
			../tcp/TCPProtocol.cc \
			../tcp/TCPInfo.cc \
			../http/HTTPInfo.cc \
			../ssl/SSLInfo.cc \
			../smtp/SMTPInfo.cc \
			../../regex/RegexManager.cc \
			../../regex/Regex.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainName.cc \
			../dns/DNSProtocol.cc \
			../icmp/ICMPProtocol.cc \
			OpenFlowProtocol.cc test_openflow.cc

test_openflow_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_openflow_LDADD   = $(BOOST_LDFLAGS) $(PCRE_LIB) $(LOG4CXX_FLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

