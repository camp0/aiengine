#include <string>
#include "FlowCache.h"
#include "FlowManager.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE flowtest 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (flowcache) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1_flowcache)
{
	std::cout << "Test 1"<< std::endl;
	FlowCache *fc = new FlowCache(); 
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);

	fc->createFlows(1000);
	BOOST_CHECK(fc->getTotalFlows() == 1000);
	fc->destroyFlows(10000);
	BOOST_CHECK(fc->getTotalFlows() == 0);
	delete fc;	
}

BOOST_AUTO_TEST_CASE (test2_flowcache)
{
	std::cout << "Test 2"<< std::endl;
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

	fc->releaseFlow(f1);
	fc->destroyFlows(1);	
	delete fc;
}

BOOST_AUTO_TEST_CASE (test3_flowcache)
{
        std::cout << "Test 3"<< std::endl;

        FlowCache *fc = new FlowCache();
        fc->createFlows(10);

	Flow *f1 = fc->acquireFlow();
	Flow *f2 = fc->acquireFlow();
	Flow *f3 = fc->acquireFlow();
	
	BOOST_CHECK(fc->getTotalFlowsOnCache() == 7);
	BOOST_CHECK(fc->getTotalFlows() == 10);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 3);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(f2 != f1);
	BOOST_CHECK(f1 != f3);
	
	fc->releaseFlow(f1);
	fc->releaseFlow(f2);
	fc->releaseFlow(f3);
	BOOST_CHECK(fc->getTotalReleases() == 3);

	fc->destroyFlows(fc->getTotalFlows());
	delete fc;
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowmanager) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1_flowmanager_lookups)
{
	std::cout << "Test 4"<< std::endl;

	FlowManager *fm = new FlowManager();
	FlowPtr f1 = FlowPtr(new Flow());

	unsigned long h1 = 1^2^3^4^5;
	unsigned long h2 = 4^5^3^1^2;
	unsigned long hfail = 10^10^10^10^10; // for fails

	f1->setId(h1);
	fm->addFlow(f1);
	BOOST_CHECK(fm->getNumberFlows() == 1);

	FlowPtr f2 = fm->findFlow(hfail,h2);
	BOOST_CHECK(f1 == f2);
	BOOST_CHECK(f1.get() == f2.get());

	FlowPtr f3 = fm->findFlow(hfail,hfail);
	BOOST_CHECK(f3.get() == 0);
	BOOST_CHECK(fm->getNumberFlows() == 1);
	delete fm;
}

BOOST_AUTO_TEST_CASE (test2_flowmanager_lookups_remove)
{
        std::cout << "Test 4"<< std::endl;

        FlowManager *fm = new FlowManager();
        FlowPtr f1 = FlowPtr(new Flow());

        unsigned long h1 = 1^2^3^4^5;
        unsigned long h2 = 4^5^3^1^2;
        unsigned long hfail = 10^10^10^10^10; // for fails

        f1->setId(h1);
    
	BOOST_CHECK(f1.use_count() == 1); 
	fm->addFlow(f1);
	BOOST_CHECK(f1.use_count() == 2); 
        BOOST_CHECK(fm->getNumberFlows() == 1);

        f1 = fm->findFlow(hfail,h2);

	fm->removeFlow(f1);
	BOOST_CHECK(f1.use_count() == 1); 
        BOOST_CHECK(fm->getNumberFlows() == 0);

        delete fm;
}



BOOST_AUTO_TEST_SUITE_END( )
