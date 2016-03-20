AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	test_ssdp.h SSDPInfo.h SSDPProtocol.h

TEST = test_ssdp

check_PROGRAMS = test_ssdp

test_ssdp_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
			../../FlowForwarder.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../protocols/ethernet/EthernetProtocol.cc \
			../../protocols/ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
                        ../tcp/TCPInfo.cc \
                        ../http/HTTPInfo.cc \
                        ../ssl/SSLInfo.cc \
                        ../smtp/SMTPInfo.cc \
                        ../dns/DNSInfo.cc \
                        ../gprs/GPRSInfo.cc \
                        ../sip/SIPInfo.cc \
			../../protocols/udp/UDPProtocol.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainName.cc \
			SSDPProtocol.cc test_ssdp.cc

test_ssdp_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_ssdp_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

