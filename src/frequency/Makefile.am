AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =	PacketFrequencies.h \
			FrequencyGroupItem.h \
			test_frequency.h FrequencyCounter.h FrequencyGroup.h FrequencyGroup_Impl.h

TEST = test_frequency

check_PROGRAMS = test_frequency

test_frequency_SOURCES = 	../Multiplexer.cc ../FlowForwarder.cc \
			../ethernet/EthernetProtocol.cc \
			../ip/IPProtocol.cc \
			../tcp/TCPProtocol.cc \
			../flow/FlowManager.cc \
			FrequencyProtocol.cc test_frequency.cc

test_frequency_CPPFLAGS = -DSTAND_ALONE
test_frequency_LDADD   = -lboost_unit_test_framework

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

