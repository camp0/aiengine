AUTOMAKE_OPTIONS = gnu

if HAVE_LIBLOG4CXX
  LOG4CXX_FLAGS = -llog4cxx
else
  LOG4CXX_FLAGS =
endif

noinst_HEADERS =	PacketFrequencies.h \
			FrequencyGroupItem.h \
			test_frequency.h FrequencyCounter.h FrequencyGroup.h FrequencyGroup_Impl.h

TEST = test_frequency

check_PROGRAMS = test_frequency

test_frequency_SOURCES = 	../../Multiplexer.cc \
				../../FlowForwarder.cc \
				../../Protocol.cc ../../CacheManager.cc \
				../../AnomalyManager.cc \
				../ethernet/EthernetProtocol.cc \
				../ip/IPProtocol.cc \
				../../ipset/IPSetManager.cc \
				../../ipset/IPSet.cc \
				../tcp/TCPProtocol.cc \
				../../flow/FlowManager.cc \
				../../Flow.cc \
				FrequencyProtocol.cc FrequencyCounter.cc test_frequency.cc

test_frequency_CPPFLAGS = -I../.. $(BOOST_CPPFLAGS) -DSTAND_ALONE
test_frequency_LDADD   = $(BOOST_LDFLAGS) $(LOG4CXX_FLAGS) -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

