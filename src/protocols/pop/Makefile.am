AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	test_pop.h POPInfo.h

TEST = test_pop

check_PROGRAMS = test_pop

test_pop_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
			../../FlowForwarder.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../protocols/ethernet/EthernetProtocol.cc \
			../../protocols/ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../../protocols/tcp/TCPProtocol.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainName.cc \
			../../names/DomainNameManager.cc \
			../tcp/TCPInfo.cc \
			../http/HTTPInfo.cc \
			../ssl/SSLInfo.cc \
			../smtp/SMTPInfo.cc \
			../bitcoin/BitcoinInfo.cc \
			../dns/DNSInfo.cc \
			../gprs/GPRSInfo.cc \
			../sip/SIPInfo.cc \
			../ssdp/SSDPInfo.cc \
			POPProtocol.cc test_pop.cc

test_pop_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_pop_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

