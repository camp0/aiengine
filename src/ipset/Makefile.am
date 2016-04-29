AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	test_ipset.h IPAbstractSet.h IPBloomSet.h

TEST = test_ipset

check_PROGRAMS = test_ipset

test_ipset_SOURCES = 	../Multiplexer.cc  \
			../FlowForwarder.cc \
			../Flow.cc ../CacheManager.cc \
			../AnomalyManager.cc \
			../flow/FlowManager.cc \
			../protocols/ethernet/EthernetProtocol.cc \
			../protocols/vlan/VLanProtocol.cc \
			../protocols/ip/IPProtocol.cc \
			../protocols/tcp/TCPProtocol.cc \
			../protocols/tcp/TCPInfo.cc \
			../protocols/ssl/SSLInfo.cc \
			../protocols/http/HTTPInfo.cc \
			../protocols/smtp/SMTPInfo.cc \
			../protocols/bitcoin/BitcoinInfo.cc \
			../protocols/udp/UDPProtocol.cc \
			../protocols/dns/DNSInfo.cc \
			../protocols/gprs/GPRSInfo.cc \
			../protocols/sip/SIPInfo.cc \
			../protocols/ssdp/SSDPInfo.cc \
			../protocols/coap/CoAPInfo.cc \
                        ../protocols/imap/IMAPInfo.cc \
                        ../protocols/pop/POPInfo.cc \
                        ../protocols/mqtt/MQTTInfo.cc \
			../protocols/udpgeneric/UDPGenericProtocol.cc \
			../protocols/tcpgeneric/TCPGenericProtocol.cc \
			../regex/RegexManager.cc \
			../regex/Regex.cc \
			IPAbstractSet.cc IPSet.cc \
			IPBloomSet.cc \
			IPSetManager.cc test_ipset.cc 

test_ipset_CPPFLAGS = -I../ $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_ipset_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework -lpcre $(LOG4CXX_FLAGS)

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

