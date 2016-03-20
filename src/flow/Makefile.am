AUTOMAKE_OPTIONS = gnu

TEST = test_flows 

check_PROGRAMS = test_flows 

test_flows_CPPFLAGS = -g -I../ $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_flows_SOURCES =     ../Flow.cc \
			../protocols/tcp/TCPInfo.cc \
			../protocols/http/HTTPInfo.cc \
			../protocols/ssl/SSLInfo.cc \
			../protocols/smtp/SMTPInfo.cc \
			../protocols/dns/DNSInfo.cc \
			../protocols/gprs/GPRSInfo.cc \
			../protocols/sip/SIPInfo.cc \
			../CacheManager.cc \
			../AnomalyManager.cc FlowManager.cc test_flows.cc
test_flows_LDADD   = $(BOOST_LDFLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

