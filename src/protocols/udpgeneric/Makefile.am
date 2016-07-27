include $(top_srcdir)/src/common.mk

AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	test_udpgeneric.h

TEST = test_udpgeneric

check_PROGRAMS = test_udpgeneric

test_udpgeneric_SOURCES = 	../../Multiplexer.cc ../../Protocol.cc \
				../../FlowForwarder.cc ../../CacheManager.cc \
				../../AnomalyManager.cc \
				../ethernet/EthernetProtocol.cc \
				../ip/IPProtocol.cc \
				../../ipset/IPSetManager.cc \
				../../ipset/IPSet.cc \
				../udp/UDPProtocol.cc \
                        	$(TEST_FLOW_OBJECTS) \
				../../Flow.cc \
				../../flow/FlowManager.cc \
				../../regex/RegexManager.cc \
				../../regex/Regex.cc \
				UDPGenericProtocol.cc test_udpgeneric.cc

test_udpgeneric_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_udpgeneric_LDADD   = $(BOOST_LDFLAGS) $(PCRE_LIB) $(LOG4CXX_FLAGS) -lboost_unit_test_framework 

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `
