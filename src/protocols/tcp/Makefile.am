AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_tcp.h TCPStates.h TCPProtocol.h TCPInfo.h TCPHeader.h \
			TCPRawSocket.h

TEST = test_tcp

check_PROGRAMS = test_tcp

test_tcp_SOURCES = 	../../Multiplexer.cc  \
			../../FlowForwarder.cc \
			../../Flow.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../flow/FlowManager.cc \
			../ethernet/EthernetProtocol.cc \
			../vlan/VLanProtocol.cc \
			../ip/IPProtocol.cc \
			../dns/DNSInfo.cc \
			../http/HTTPInfo.cc \
			../ssl/SSLInfo.cc \
                        ../gprs/GPRSInfo.cc \
                        ../sip/SIPInfo.cc \
                        ../ssdp/SSDPInfo.cc \
                        ../smtp/SMTPInfo.cc \
                        ../bitcoin/BitcoinInfo.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../ip6/IPv6Protocol.cc \
			TCPInfo.cc TCPHeader.cc TCPProtocol.cc \
			test_tcp.cc

test_tcp_CPPFLAGS = -I../../  $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_tcp_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

