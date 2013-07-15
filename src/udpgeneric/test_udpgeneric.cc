#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../ip/IPProtocol.h"
#include "../udp/UDPProtocol.h"
#include "UDPGenericProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE ssltest 
#include <boost/test/unit_test.hpp>

struct StackUDPGenericTest
{
};

BOOST_FIXTURE_TEST_SUITE(udpgeneric_suite,StackUDPGenericTest)

BOOST_AUTO_TEST_CASE (test1_udpgeneric)
{

}


BOOST_AUTO_TEST_SUITE_END( )

