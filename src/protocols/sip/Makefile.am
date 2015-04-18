AUTOMAKE_OPTIONS = gnu

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
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../regex/Regex.cc \
			SIPProtocol.cc test_sip.cc

test_sip_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_sip_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework -lboost_regex $(PCRE_LIB)

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

