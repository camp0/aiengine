#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../ip/IPProtocol.h"
#include "../tcp/TCPProtocol.h"
#include "TCPGenericProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE tcpgenerictest 
#include <boost/test/unit_test.hpp>


struct StackTCPGenericTest {};


BOOST_FIXTURE_TEST_SUITE(tcpgeneric_suite,StackTCPGenericTest)

BOOST_AUTO_TEST_CASE (test1_tcpgeneric)
{

}


BOOST_AUTO_TEST_SUITE_END( )

