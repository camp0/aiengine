AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

TEST = test_sip

check_PROGRAMS = test_sip

noinst_HEADERS = 	SIPProtocol.h SIPInfo.h test_sip.h

test_sip_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
			../../FlowForwarder.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../ip6/IPv6Protocol.cc \
			../udp/UDPProtocol.cc \
			../gprs/GPRSInfo.cc \
			../dns/DNSInfo.cc \
			../ssdp/SSDPInfo.cc \
			../tcp/TCPInfo.cc \
			../ssl/SSLInfo.cc \
			../http/HTTPInfo.cc \
			../smtp/SMTPInfo.cc \
			../bitcoin/BitcoinInfo.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainName.cc \
			../../regex/Regex.cc \
			SIPInfo.cc SIPProtocol.cc test_sip.cc

test_sip_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_sip_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework $(LOG4CXX_FLAGS) $(PCRE_LIB)

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

