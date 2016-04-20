AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	test_smtp.h SMTPInfo.h

TEST = test_smtp

check_PROGRAMS = test_smtp

test_smtp_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
			../../FlowForwarder.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../StringCache.cc \
			../../protocols/ethernet/EthernetProtocol.cc \
			../../protocols/ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../tcp/TCPProtocol.cc \
			../tcp/TCPInfo.cc \
			../ssl/SSLInfo.cc \
			../bitcoin/BitcoinInfo.cc \
			../http/HTTPInfo.cc \
			../gprs/GPRSInfo.cc \
			../dns/DNSInfo.cc \
			../sip/SIPInfo.cc \
			../ssdp/SSDPInfo.cc \
			../coap/CoAPInfo.cc \
                        ../pop/POPInfo.cc \
                        ../imap/IMAPInfo.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainName.cc \
			SMTPInfo.cc SMTPProtocol.cc test_smtp.cc

test_smtp_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_smtp_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

