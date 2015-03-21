AUTOMAKE_OPTIONS = gnu

TEST = test_http

check_PROGRAMS = test_http

noinst_HEADERS = 	HTTPProtocol.h HTTPInfo.h HTTPUriSet.h test_http.h

test_http_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
			../../FlowForwarder.cc ../../CacheManager.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../ip6/IPv6Protocol.cc \
			../tcp/TCPProtocol.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../regex/Regex.cc \
			HTTPUriSet.cc \
			HTTPProtocol.cc test_http.cc

test_http_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_http_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework $(PCRE_LIB)

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

