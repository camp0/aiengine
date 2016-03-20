AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	BitcoinInfo.h test_bitcoin.h

TEST = test_bitcoin

check_PROGRAMS = test_bitcoin

test_bitcoin_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPSetManager.cc \
			../tcp/TCPProtocol.cc \
                        ../tcp/TCPInfo.cc \
                        ../http/HTTPInfo.cc \
                        ../ssl/SSLInfo.cc \
                        ../smtp/SMTPInfo.cc \
                        ../dns/DNSInfo.cc \
                        ../gprs/GPRSInfo.cc \
                        ../sip/SIPInfo.cc \
			BitcoinProtocol.cc test_bitcoin.cc

test_bitcoin_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_bitcoin_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

