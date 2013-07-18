AUTOMAKE_OPTIONS = gnu

EXTRA_DIST = py_wrapper.cc setup.py

noinst_HEADERS =        Packet.h \
			Protocol.h \
			PacketDispatcher.h \
			NetworkStack.h \
			StackLan.h \
			Stack3G.h \
			Multiplexer.h \
			FlowForwarder.h \
			./ethernet/EthernetProtocol.h \
			./vlan/VLanProtocol.h \
			./ip/IPProtocol.h \
			./icmp/ICMPProtocol.h \
			./udp/UDPProtocol.h \
			./tcp/TCPProtocol.h \
			./gprs/GPRSProtocol.h \
			./http/HTTPProtocol.h \
			./ssl/SSLProtocol.h \
			./dns/DNSProtocol.h \
                        ./flow/FlowCache.h \
                        ./flow/FlowManager.h \
                        ./flow/Flow.h

iaengine_core_sources =	Multiplexer.cc \
			FlowForwarder.cc \
			PacketDispatcher.cc \
			./flow/FlowCache.cc \
			./flow/FlowManager.cc \
			./ethernet/EthernetProtocol.cc \
			./vlan/VLanProtocol.cc \
			./ip/IPProtocol.cc \
			./icmp/ICMPProtocol.cc \
			./udp/UDPProtocol.cc \
			./tcp/TCPProtocol.cc \
			./gprs/GPRSProtocol.cc \
			./http/HTTPProtocol.cc \
			./ssl/SSLProtocol.cc \
			./dns/DNSProtocol.cc \
			Stack3G.cc StackLan.cc 

iaengine_SOURCES =      $(iaengine_core_sources) main.cc

iaengine_CPPFLAGS = $(BOOST_CPPFLAGS)
iaengine_LDFLAGS = -DBOOST_ASIO_DISABLE_EPOLL -lpthread -lstdc++ -lboost_system -lboost_thread -lboost_program_options -lboost_regex -lpcap
iaengine_LDADD = $(BOOST_LIBS)

bin_PROGRAMS = iaengine

TEST = tests 

check_PROGRAMS = tests 

tests_SOURCES = $(iaengine_core_sources) tests.cc 
tests_LDADD   = -lboost_system -lboost_unit_test_framework -lboost_regex -lpcap
tests_LDFLAGS = -DBOOST_ASIO_DISABLE_EPOLL

BUILT_SOURCES = $(srcdir)/pyiaengine.so

$(srcdir)/pyiaengine.so: py_wrapper.cc
        g++ -fPIC $(iaengine_core_sources) \
                py_wrapper.cc `pkg-config --cflags python-2.7` \
                -I/usr/include/boost/python -std=c++11 -lpthread -lstdc++ -lboost_system \
                -lboost_thread -lboost_regex -lboost_python -lpython2.7 -o pyiaengine.so -shared

CLEANFILES = *.o *.lo *.so

MAINTAINERCLEANFILES = \
        $(srcdir)/Makefile \
        $(srcdir)/Makefile.in \
        `rm -rf $(srcdir)/build `

