#include "test_dns.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE dnstest
#endif
#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(dns_suite,StackDNStest)

BOOST_AUTO_TEST_CASE (test1_dns)
{

}


BOOST_AUTO_TEST_SUITE_END( )

