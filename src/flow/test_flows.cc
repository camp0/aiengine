#include <string>
#include "FlowCache.h"
#include "FlowManager.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE flowtest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (flowtest) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1_flowcache)
{
	FlowCache *fc = new FlowCache(); 
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);

	fc->createFlows(1000);
	BOOST_CHECK(fc->getTotalFlows() == 1000);
	fc->destroyFlows(10000);
	delete fc;	
}

BOOST_AUTO_TEST_CASE (test2_flowcache)
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
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);

	fc->createFlows(1);
	Flow *f1 = fc->acquireFlow();
	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);

	Flow *f2 = fc->acquireFlow();
	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 1);
	BOOST_CHECK(f2 == nullptr);
	
	//fc->destroyFlows(1);	
	delete fc;
}

BOOST_AUTO_TEST_CASE (test_flowmanager_lookups)
{
	FlowCache *fc = new FlowCache();
	FlowManager *fm = new FlowManager();

	fc->createFlows(10);
	Flow *f1 = fc->acquireFlow();
	BOOST_CHECK(fc->getTotalFlows() == 10);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);

	unsigned long h1 = 1^2^3^4^5;
	unsigned long h2 = 4^5^3^1^2;
	unsigned long hfail = 10^10^10^10^10; // for fails

	f1->setId(h1);
	fm->addFlow(f1);
	BOOST_CHECK(fm->getNumberFlows() == 1);

	Flow *f2 = fm->findFlow(h1,hfail);
	BOOST_CHECK(f1 == f2);
	f2 = fm->findFlow(hfail,h1);
	BOOST_CHECK(f1 == f2);
	f2 = fm->findFlow(hfail,hfail);
	BOOST_CHECK(f2 == nullptr);

	BOOST_CHECK(fm->getNumberFlows() == 1);
	fm->removeFlow(hfail,h1);
	BOOST_CHECK(fm->getNumberFlows() == 0);
	fc->releaseFlow(f1);
	BOOST_CHECK(fc->getTotalFlows() == 10);

	delete fc;
	delete fm;
}

BOOST_AUTO_TEST_SUITE_END( )
