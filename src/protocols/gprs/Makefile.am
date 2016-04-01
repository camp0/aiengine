AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS = 	GPRSInfo.h test_gprs.h

TEST = test_gprs

check_PROGRAMS = test_gprs

test_gprs_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
			../../FlowForwarder.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../udp/UDPProtocol.cc \
			../icmp/ICMPProtocol.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainName.cc \
			../dns/DNSProtocol.cc \
			../dns/DNSInfo.cc \
			../sip/SIPInfo.cc \
			../ssdp/SSDPInfo.cc \
			../http/HTTPInfo.cc \
			../ssl/SSLInfo.cc \
			../smtp/SMTPInfo.cc \
			../tcp/TCPInfo.cc \
			../bitcoin/BitcoinInfo.cc \
			GPRSInfo.cc GPRSProtocol.cc test_gprs.cc

test_gprs_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_gprs_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

