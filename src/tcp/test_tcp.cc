#include <string>
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "TCPProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE tcptest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (tcp_suite) // name of the test suite is stringtest

// check a TCP header values
//
BOOST_AUTO_TEST_CASE (test1_tcp)
{
	TCPProtocol *tcp = new TCPProtocol();
	

	delete tcp;
}

BOOST_AUTO_TEST_SUITE_END( )

