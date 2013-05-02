#include <string>
#include "FlowCache.h"
#include "FlowManager.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE flowtest 
#include <boost/test/unit_test.hpp>


BOOST_AUTO_TEST_SUITE (flowtest) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test_flowcache)
{
	FlowCache *fc = new FlowCache(); 
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);

	fc->createFlows(10);
	BOOST_CHECK(fc->getTotalFlows() == 10);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);

	fc->destroyFlows(9);
	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);

	fc->destroyFlows(9);
	BOOST_CHECK(fc->getTotalFlows() == 0);

	fc->createFlows(1);
	const Flow *f1 = fc->getFlow();
	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);

	const Flow *f2 = fc->getFlow();
	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 1);
	BOOST_CHECK(f2 == nullptr);
		
	delete fc;
}

BOOST_AUTO_TEST_CASE (test_flowcache_flowmanager)
{
	FlowCache *fc = new FlowCache();
	FlowManager *fm = new FlowManager();

	fc->createFlows(10);
	Flow *f = fc->getFlow();
	fm->addFlow(f);

	delete fc;
	delete fm;
}

BOOST_AUTO_TEST_SUITE_END( )
