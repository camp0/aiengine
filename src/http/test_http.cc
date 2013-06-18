#include <string>
#include "../../test/tests_packets.h"
#include "../Protocol.h"
#include "../Multiplexer.h"
#include "../ethernet/EthernetProtocol.h"
#include "../vlan/VLanProtocol.h"
#include "HTTPProtocol.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE httptest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(http_suite)

BOOST_AUTO_TEST_CASE (test1_http)
{
}


BOOST_AUTO_TEST_SUITE_END( )

