#include <string>
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "../ip/IPProtocol.h"
#include "UDPProtocol.h"


#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE udptest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (udp_suite) // name of the test suite is stringtest

// check a IP header values
//
BOOST_AUTO_TEST_CASE (test1_udp)
{
	UDPProtocol *udp = new UDPProtocol();

	BOOST_CHECK(udp->getTotalPackets() == 0);

	delete udp;	
}


BOOST_AUTO_TEST_SUITE_END( )

