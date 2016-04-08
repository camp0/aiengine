AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	test_modbus.h

TEST = test_modbus

check_PROGRAMS = test_modbus

test_modbus_SOURCES = 	../../Multiplexer.cc \
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
                        ../bitcoin/BitcoinInfo.cc \
                        ../dns/DNSInfo.cc \
                        ../gprs/GPRSInfo.cc \
                        ../sip/SIPInfo.cc \
                        ../ssdp/SSDPInfo.cc \
                        ../coap/CoAPInfo.cc \
                        ../pop/POPInfo.cc \
                        ../imap/IMAPInfo.cc \
			ModbusProtocol.cc test_modbus.cc

test_modbus_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_modbus_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

