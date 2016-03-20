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
			../../protocols/ethernet/EthernetProtocol.cc \
			../../protocols/ip/IPProtocol.cc \
			../../ipset/IPSetManager.cc \
			../../ipset/IPSet.cc \
			../../protocols/tcp/TCPProtocol.cc \
			../../protocols/tcp/TCPInfo.cc \
			../../protocols/ssl/SSLInfo.cc \
			../../protocols/http/HTTPInfo.cc \
			../../protocols/gprs/GPRSInfo.cc \
			../../protocols/dns/DNSInfo.cc \
			../../protocols/sip/SIPInfo.cc \
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

