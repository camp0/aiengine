AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =        5tuple.h \
                        ./flow/FlowCache.h \
                        ./flow/FlowManager.h \
                        ./flow/Flow.h

iaengine_core_sources = ./flow/FlowCache.cc \
			./flow/FlowManager.cc 

iaengine_SOURCES =      $(iaengine_core_sources) main.cc

iaengine_CPPFLAGS = $(BOOST_CPPFLAGS)
iaengine_LDFLAGS = -lpthread -lstdc++ -lboost_system -lboost_thread -lboost_program_options -lboost_regex
iaengine_LDADD = $(BOOST_LIBS)

bin_PROGRAMS = iaengine

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

