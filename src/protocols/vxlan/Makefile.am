include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	test_vxlan.h

TEST = test_vxlan

check_PROGRAMS = test_vxlan

test_vxlan_SOURCES = 	../../Multiplexer.cc \
			../../Protocol.cc ../../CacheManager.cc \
			../../StringCache.cc \
			../ethernet/EthernetProtocol.cc \
			../../Flow.cc \
			../../AnomalyManager.cc \
			../../FlowForwarder.cc \
			../../flow/FlowManager.cc \
			../ip/IPProtocol.cc \
			../../ipset/IPSet.cc \
			../../ipset/IPSetManager.cc \
			../udp/UDPProtocol.cc \
			$(TEST_FLOW_OBJECTS) \
			../tcp/TCPProtocol.cc \
			../../names/DomainNameManager.cc \
			../../names/DomainName.cc \
			../dns/DNSProtocol.cc \
			../icmp/ICMPProtocol.cc \
			VxLanProtocol.cc test_vxlan.cc

test_vxlan_CPPFLAGS = -I../.. -g $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_vxlan_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

