AUTOMAKE_OPTIONS = gnu

noinst_HEADERS =        Packet.h \
			Protocol.h \
			PacketDispatcher.h \
			Multiplexer.h \
			Message.h \
			FiveTuple.h \
                        ./ip/IPMessage.h \
                        ./flow/FlowCache.h \
                        ./flow/FlowManager.h \
                        ./flow/Flow.h

iaengine_core_sources =	Multiplexer.cc \
			PacketDispatcher.cc \
			./flow/FlowCache.cc \
			./flow/FlowManager.cc \
			./ethernet/EthernetProtocol.cc \
			./ip/IPProtocol.cc \
			./icmp/ICMPProtocol.cc \
			./udp/UDPProtocol.cc \
			./tcp/TCPProtocol.cc 

iaengine_SOURCES =      $(iaengine_core_sources) main.cc

iaengine_CPPFLAGS = $(BOOST_CPPFLAGS)
iaengine_LDFLAGS = -DBOOST_ASIO_DISABLE_EPOLL -lpthread -lstdc++ -lboost_system -lboost_thread -lboost_program_options -lboost_regex -lpcap
iaengine_LDADD = $(BOOST_LIBS)

bin_PROGRAMS = iaengine

TEST = tests 

check_PROGRAMS = tests 

tests_SOURCES = $(iaengine_core_sources) tests.cc 
tests_LDADD   = -lboost_system -lboost_unit_test_framework -lpcap
tests_LDFLAGS = -DBOOST_ASIO_DISABLE_EPOLL

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

