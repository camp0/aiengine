AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

TEST = test_http

check_PROGRAMS = test_http

noinst_HEADERS = 	HTTPProtocol.h HTTPInfo.h HTTPUriSet.h test_http.h

test_http_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
			../../FlowForwarder.cc ../../CacheManager.cc \
			../../AnomalyManager.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../ip6/IPv6Protocol.cc \
			../tcp/TCPProtocol.cc \
			../gprs/GPRSInfo.cc \
			../sip/SIPInfo.cc \
			../tcp/TCPInfo.cc \
			../smtp/SMTPInfo.cc \
			../dns/DNSInfo.cc \
			../ssl/SSLInfo.cc \
			../../Flow.cc \
			../../flow/FlowManager.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainName.cc \
			../../regex/RegexManager.cc \
			../../regex/Regex.cc \
			HTTPUriSet.cc \
			HTTPInfo.cc HTTPProtocol.cc test_http.cc

test_http_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_http_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_unit_test_framework $(PCRE_LIB)

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

