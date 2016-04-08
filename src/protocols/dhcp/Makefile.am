AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_dhcp.h

TEST = test_dhcp

check_PROGRAMS = test_dhcp

test_dhcp_SOURCES = 	../../Multiplexer.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
                        ../tcp/TCPInfo.cc \
                        ../http/HTTPInfo.cc \
                        ../ssl/SSLInfo.cc \
                        ../smtp/SMTPInfo.cc \
                        ../bitcoin/BitcoinInfo.cc \
                        ../dns/DNSInfo.cc \
                        ../gprs/GPRSInfo.cc \
                        ../sip/SIPInfo.cc \
                        ../ssdp/SSDPInfo.cc \
                        ../coap/CoAPInfo.cc \
			../imap/IMAPInfo.cc \
			../pop/POPInfo.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			DHCPProtocol.cc test_dhcp.cc

test_dhcp_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_dhcp_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

