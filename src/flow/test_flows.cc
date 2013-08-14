/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 *
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#include <string>
#include "FlowCache.h"
#include "FlowManager.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE flowtest
#endif
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (flowcache) // name of the test suite is stringtest

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
	BOOST_CHECK(fc->getTotalFlows() == 0);
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
	BOOST_CHECK(fc->getTotalFlowsOnCache() == 10);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);
	BOOST_CHECK(fc->getTotalFails() == 0);

	fc->destroyFlows(9);
	BOOST_CHECK(fc->getTotalFlowsOnCache() == 1);
	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);

	fc->destroyFlows(9);
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 0);

	fc->createFlows(1);
	BOOST_CHECK(fc->getTotalFlowsOnCache() == 1);
	BOOST_CHECK(fc->getTotalFlows() == 1);

	FlowPtr f1 = fc->acquireFlow().lock();

	BOOST_CHECK(fc->getTotalFlowsOnCache() == 0);
	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);

	FlowPtr f2 = fc->acquireFlow().lock();
	BOOST_CHECK(fc->getTotalFlows() == 1);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 1);
	BOOST_CHECK(fc->getTotalFlowsOnCache() == 0);
	BOOST_CHECK(f2 == nullptr);

	fc->releaseFlow(f1);
	fc->destroyFlows(1);	
	delete fc;

}

BOOST_AUTO_TEST_CASE (test3_flowcache)
{
        FlowCache *fc = new FlowCache();
        fc->createFlows(10);

	FlowPtr f1 = fc->acquireFlow().lock();
	FlowPtr f2 = fc->acquireFlow().lock();
	FlowPtr f3 = fc->acquireFlow().lock();
	
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

BOOST_AUTO_TEST_CASE (test4_flowcache)
{
        FlowCache *fc = new FlowCache();
        fc->createFlows(1);

        FlowPtr f1 = fc->acquireFlow().lock();

	BOOST_CHECK(fc->getTotalFlowsOnCache() == 0);
	f1->setId(10);
	f1->total_bytes = 10;
	f1->total_packets = 10;

        fc->releaseFlow(f1);
	BOOST_CHECK(fc->getTotalFlowsOnCache() == 1);
        BOOST_CHECK(fc->getTotalReleases() == 1);

	FlowPtr f2 = fc->acquireFlow().lock();
        fc->destroyFlows(fc->getTotalFlows());
        delete fc;
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowmanager) // name of the test suite is stringtest


BOOST_AUTO_TEST_CASE (test1_flowmanager_lookups)
{
	FlowManager *fm = new FlowManager();
	FlowPtr f1 = FlowPtr(new Flow());

	unsigned long h1 = 1^2^3^4^5;
	unsigned long h2 = 4^5^3^1^2;
	unsigned long hfail = 10^10^10^10^10; // for fails

	f1->setId(h1);
	fm->addFlow(f1);
	BOOST_CHECK(fm->getTotalFlows() == 1);

	FlowPtr f2 = fm->findFlow(hfail,h2);
	BOOST_CHECK(f1 == f2);
	BOOST_CHECK(f1.get() == f2.get());

	FlowPtr f3 = fm->findFlow(hfail,hfail);
	BOOST_CHECK(f3.get() == 0);
	BOOST_CHECK(fm->getTotalFlows() == 1);
	delete fm;
}

BOOST_AUTO_TEST_CASE (test2_flowmanager_lookups_remove)
{
        FlowManager *fm = new FlowManager();
        FlowPtr f1 = FlowPtr(new Flow());

        unsigned long h1 = 1^2^3^4^5;
        unsigned long h2 = 4^5^3^1^2;
        unsigned long hfail = 10^10^10^10^10; // for fails

        f1->setId(h1);
    
	BOOST_CHECK(f1.use_count() == 1); 
	fm->addFlow(f1);
	BOOST_CHECK(f1.use_count() == 2); 
        BOOST_CHECK(fm->getTotalFlows() == 1);

        f1 = fm->findFlow(hfail,h2);

	fm->removeFlow(f1);
	BOOST_CHECK(f1.use_count() == 1); 
        BOOST_CHECK(fm->getTotalFlows() == 0);

        delete fm;
}

BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowcache_and_flowmanager) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1_flowcache_flowmanager)
{
	FlowCache *fc = new FlowCache(); 
	FlowManager *fm = new FlowManager();

	fc->createFlows(10);
	FlowPtr f1 = fc->acquireFlow().lock();
	BOOST_CHECK(f1.use_count() == 2); // one is the cache and the other f1
        BOOST_CHECK(fm->getTotalFlows() == 0);
        
	unsigned long h1 = 1^2^3^4^5;
        unsigned long h2 = 4^5^3^1^2;
        unsigned long hfail = 10^10^10^10^10; // for fails
	f1->setId(h1);

	fm->addFlow(f1);
        BOOST_CHECK(fm->getTotalFlows() == 1);
	FlowPtr f2 = fm->findFlow(h1,hfail);
	BOOST_CHECK(f2.get() == f1.get());
	fm->removeFlow(f1);
        BOOST_CHECK(fm->getTotalFlows() == 0);

	delete fm;
	delete fc;
}

BOOST_AUTO_TEST_CASE (test2_flowcache_flowmanager)
{
        FlowCachePtr fc = FlowCachePtr(new FlowCache());
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
	std::vector<FlowPtr> v;
	
        fc->createFlows(64);

	for (int i = 0;i< 66; ++i)
	{
        	FlowPtr f1 = fc->acquireFlow().lock();

		if(f1)
		{
        		unsigned long h1 = 1^2^3^4^i;
        		unsigned long h2 = 4^i^3^1^2;
        		f1->setId(h1);

        		fm->addFlow(f1);
        		BOOST_CHECK(fm->getTotalFlows() == i+1);
		}
	}

	BOOST_CHECK(fm->getTotalFlows() == 64);
	BOOST_CHECK(fc->getTotalFlows() == 64);
	BOOST_CHECK(fc->getTotalAcquires() == 64);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalFails() == 2);

	for (int i = 0; i<64; ++i)
	{
        	unsigned long h1 = 1^2^3^4^i;
        	unsigned long h2 = 4^i^3^1^2;

		FlowPtr f1 = fm->findFlow(h1,h2);
		if(f1)
		{
			fm->removeFlow(f1);
			v.push_back(f1);
		}
	}
	BOOST_CHECK(fm->getTotalFlows() == 0);

	for (auto value: v)
	{
		fc->releaseFlow(value);
	}

	BOOST_CHECK(fc->getTotalReleases() == 64);
}



BOOST_AUTO_TEST_SUITE_END( )
