AUTOMAKE_OPTIONS = gnu

			
noinst_HEADERS =        PacketDispatcher.h \
			Multiplexer.h \
			Message.h \
			FiveTuple.h \
                        ./ip/IPMessage.h \
                        ./flow/FlowCache.h \
                        ./flow/FlowManager.h \
                        ./flow/Flow.h

iaengine_core_sources =	PacketDispatcher.cc \
			./flow/FlowCache.cc \
			./flow/FlowManager.cc 

iaengine_SOURCES =      $(iaengine_core_sources) main.cc

iaengine_CPPFLAGS = $(BOOST_CPPFLAGS)
iaengine_LDFLAGS = -lpthread -lstdc++ -lboost_system -lboost_thread -lboost_program_options -lboost_regex -lpcap
iaengine_LDADD = $(BOOST_LIBS)

bin_PROGRAMS = iaengine

TEST = tests_

check_PROGRAMS = tests

tests_SOURCES = tests.cc
tests_LDADD   = -lboost_unit_test_framework


CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

