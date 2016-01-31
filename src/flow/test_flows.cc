/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2016  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
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

using namespace aiengine;

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

        fc->createFlows(2);

        BOOST_CHECK(fc->getTotalFlows() == 2);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);

	SharedPointer<Flow> f1 = fc->acquireFlow();
	SharedPointer<Flow> f2 = fc->acquireFlow();
	SharedPointer<Flow> f3 = fc->acquireFlow();

        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 2);
        BOOST_CHECK(fc->getTotalFails() == 1);

	BOOST_CHECK(f1 !=  nullptr);
	BOOST_CHECK(f2 !=  nullptr);
	BOOST_CHECK(f3 ==  nullptr);

	fc->releaseFlow(f2);
	fc->releaseFlow(f1);
        
	BOOST_CHECK(fc->getTotalFlows() == 2);
        BOOST_CHECK(fc->getTotalReleases() == 2);
        BOOST_CHECK(fc->getTotalAcquires() == 2);
        BOOST_CHECK(fc->getTotalFails() == 1);

	delete fc;
}

BOOST_AUTO_TEST_CASE (test3_flowcache)
{
        FlowCache *fc = new FlowCache();

	SharedPointer<Flow> f1 = SharedPointer<Flow>(new Flow());
	SharedPointer<Flow> f2 = SharedPointer<Flow>(new Flow());
	SharedPointer<Flow> f3 = SharedPointer<Flow>(new Flow());

        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);

	fc->releaseFlow(f1);

	BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(fc->getTotalFlows() == 1);
        BOOST_CHECK(fc->getTotalReleases() == 1);
        BOOST_CHECK(fc->getTotalAcquires() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);

	SharedPointer<Flow> f4 = fc->acquireFlow();

	BOOST_CHECK(f1 == f4);

	delete fc;
}

BOOST_AUTO_TEST_CASE (test22_flowcache)
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

	BOOST_CHECK(fc->getTotalFlows() == 1);

	SharedPointer<Flow> f1 = fc->acquireFlow();

	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 0);

	SharedPointer<Flow> f2 = fc->acquireFlow();

	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 1);
	BOOST_CHECK(fc->getTotalFails() == 1);
	BOOST_CHECK(f2 == nullptr);

	fc->releaseFlow(f1);
	fc->destroyFlows(1);	
	delete fc;

}

BOOST_AUTO_TEST_CASE (test23_flowcache)
{
        FlowCache *fc = new FlowCache();
        fc->createFlows(10);

	SharedPointer<Flow> f1 = fc->acquireFlow();
	SharedPointer<Flow> f2 = fc->acquireFlow();
	SharedPointer<Flow> f3 = fc->acquireFlow();
	
	BOOST_CHECK(fc->getTotalFlows() == 7);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 3);
	BOOST_CHECK(fc->getTotalFails() == 0);
	BOOST_CHECK(f2 != f1);
	BOOST_CHECK(f1 != f3);
	
	fc->releaseFlow(f1);
	fc->releaseFlow(f2);
	fc->releaseFlow(f3);
	BOOST_CHECK(fc->getTotalReleases() == 3);
	BOOST_CHECK(fc->getTotalFlows() == 10);

	fc->destroyFlows(fc->getTotalFlows());
	delete fc;
}

BOOST_AUTO_TEST_CASE (test24_flowcache)
{
        FlowCache *fc = new FlowCache();
        fc->createFlows(1);

        SharedPointer<Flow> f1 = fc->acquireFlow();

	BOOST_CHECK(fc->getTotalFlows() == 0);

	f1->setId(10);
	f1->total_bytes = 10;
	f1->total_packets = 10;

        fc->releaseFlow(f1);
	BOOST_CHECK(fc->getTotalFlows() == 1);
        BOOST_CHECK(fc->getTotalReleases() == 1);

	SharedPointer<Flow> f2 = fc->acquireFlow();
        fc->destroyFlows(fc->getTotalFlows());
        delete fc;
}

BOOST_AUTO_TEST_CASE (test25_flow_serialize)
{
        FlowCache *fc = new FlowCache();
        fc->createFlows(1);

        SharedPointer<Flow> f1 = fc->acquireFlow();

	f1->setFiveTuple(inet_addr("192.168.1.1"),2345,6,inet_addr("54.12.5.1"),80);

	std::ostringstream os;
#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION
	std::string output("{\"5tuple\":\"192.168.1.1:2345:6:54.12.5.1:80\",\"b\":0,\"p\":\"None\"}");
#else
	std::string output("{\"ipsrc\":\"192.168.1.1\",\"portsrc\":2345,\"proto\":6,\"ipdst\":\"54.12.5.1\",\"portdst\":80,\"bytes\":0,\"layer7\":\"None\"}");
#endif
	f1->serialize(os);

	BOOST_CHECK(output.compare(os.str()) == 0);

        fc->releaseFlow(f1);
        BOOST_CHECK(fc->getTotalFlows() == 1);
        BOOST_CHECK(fc->getTotalReleases() == 1);

        fc->destroyFlows(fc->getTotalFlows());
        delete fc;
}


BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowmanager) // name of the test suite is stringtest


BOOST_AUTO_TEST_CASE (test1_flowmanager_lookups)
{
	FlowManager *fm = new FlowManager();
	SharedPointer<Flow> f1 = SharedPointer<Flow>(new Flow());

	unsigned long h1 = 1^2^3^4^5;
	unsigned long h2 = 4^5^3^1^2;
	unsigned long hfail = 10^10^10^10^10; // for fails

	f1->setId(h1);
	fm->addFlow(f1);
	BOOST_CHECK(fm->getTotalFlows() == 1);

	SharedPointer<Flow> f2 = fm->findFlow(hfail,h2);
	BOOST_CHECK(f1 == f2);
	BOOST_CHECK(f1.get() == f2.get());

	SharedPointer<Flow> f3 = fm->findFlow(hfail,hfail);
	BOOST_CHECK(f3.get() == 0);
	BOOST_CHECK(fm->getTotalFlows() == 1);

	delete fm;
}

BOOST_AUTO_TEST_CASE (test2_flowmanager_lookups_remove)
{
        FlowManager *fm = new FlowManager();
        SharedPointer<Flow> f1 = SharedPointer<Flow>(new Flow());

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
	// BOOST_CHECK(f1.use_count() == 1); 
	// TOOD: BOOST_CHECK(f1.use_count() == 1); 
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
	SharedPointer<Flow> f1 = fc->acquireFlow();

	BOOST_CHECK(f1.use_count() == 1); // one is the cache and the other f1
        BOOST_CHECK(fm->getTotalFlows() == 0);
        
	unsigned long h1 = 1^2^3^4^5;
        unsigned long h2 = 4^5^3^1^2;
        unsigned long hfail = 10^10^10^10^10; // for fails
	f1->setId(h1);

	fm->addFlow(f1);
        BOOST_CHECK(fm->getTotalFlows() == 1);
	SharedPointer<Flow> f2 = fm->findFlow(h1,hfail);
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
	std::vector<SharedPointer<Flow>> v;
	
        fc->createFlows(64);

	for (int i = 0;i< 66; ++i)
	{
        	SharedPointer<Flow> f1 = fc->acquireFlow();

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
	BOOST_CHECK(fc->getTotalFlows() == 0);
	BOOST_CHECK(fc->getTotalAcquires() == 64);
	BOOST_CHECK(fc->getTotalReleases() == 0);
	BOOST_CHECK(fc->getTotalFails() == 2);

	for (int i = 0; i<64; ++i)
	{
        	unsigned long h1 = 1^2^3^4^i;
        	unsigned long h2 = 4^i^3^1^2;

		SharedPointer<Flow> f1 = fm->findFlow(h1,h2);
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

BOOST_AUTO_TEST_CASE (test3_flowcache_flowmanager)
{
        FlowCachePtr fc = FlowCachePtr(new FlowCache());
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        std::vector<SharedPointer<Flow>> v;

        fc->createFlows(254);

        for (int i = 0;i< 254; ++i) {
                SharedPointer<Flow> f1 = fc->acquireFlow();

                if(f1) {
			uint32_t ipsrc = 1;
			uint32_t ipdst = 2;
			uint16_t portsrc = 800 + i;
			uint16_t portdst = 80;
			uint16_t proto = 6;

                        unsigned long h1 = ipsrc^portsrc^proto^ipdst^portdst;
                        unsigned long h2 = ipdst^portdst^proto^ipsrc^portsrc;

                        f1->setId(h1);
			f1->setFiveTuple(ipsrc,portsrc,proto,ipdst,portdst);

                        fm->addFlow(f1);
			f1->total_packets = 1;
                        BOOST_CHECK(fm->getTotalFlows() == i+1);
                }
        }

        BOOST_CHECK(fm->getTotalFlows() == 254);
        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 254);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);

	// Now the second packet of the flow arrives
        for (int i = 0;i< 254; ++i) {
		uint32_t ipsrc = 2;
                uint32_t ipdst = 1;
                uint16_t portsrc = 80;
                uint16_t portdst = 800 + i;
                uint16_t proto = 6;
                        
		unsigned long h1 = ipsrc^portsrc^proto^ipdst^portdst;
                unsigned long h2 = ipdst^portdst^proto^ipsrc^portsrc;

		SharedPointer<Flow> f1 = fm->findFlow(h1,h2);	
		
                if(f1) {
			// The flow only have one packet
			BOOST_CHECK(f1->total_packets == 1);
			++f1->total_packets;
                } else {
			BOOST_CHECK(1 == 2); // fail
		}
        }
        BOOST_CHECK(fm->getTotalFlows() == 254);
        BOOST_CHECK(fc->getTotalFlows() == 0);
        BOOST_CHECK(fc->getTotalAcquires() == 254);
        BOOST_CHECK(fc->getTotalReleases() == 0);
        BOOST_CHECK(fc->getTotalFails() == 0);
}

BOOST_AUTO_TEST_CASE (test4_flowcache_flowmanager)
{
        FlowCachePtr fc = FlowCachePtr(new FlowCache());
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        std::vector<SharedPointer<Flow>> v;

        fc->createFlows(254);

        for (int i = 0;i< 254; ++i) {
                SharedPointer<Flow> f1 = fc->acquireFlow();

                if(f1) {
			std::ostringstream os;
	
			os << "10.253." << i << "1";	
			std::string ipsrc_str = "192.168.1.1";	
			uint32_t ipsrc = inet_addr(ipsrc_str.c_str());
                        uint32_t ipdst = inet_addr(os.str().c_str());
                        uint16_t portsrc = 1200 + i;
                        uint16_t portdst = 8080;
                        uint16_t proto = 6;

                        unsigned long h1 = ipsrc^portsrc^proto^ipdst^portdst;
                        unsigned long h2 = ipdst^portdst^proto^ipsrc^portsrc;

                        f1->setId(h1);
                        f1->setFiveTuple(ipsrc,portsrc,proto,ipdst,portdst);

                        fm->addFlow(f1);
                        f1->total_packets = 1;
                        BOOST_CHECK(fm->getTotalFlows() == i+1);
                }
        }
        // Now the second packet of the flow arrives
        for (int i = 0;i< 254; ++i) {
		std::ostringstream os;

                os << "10.253." << i << "1";
                std::string ipsrc_str = "192.168.1.1";
                uint32_t ipdst = inet_addr(ipsrc_str.c_str());
                uint32_t ipsrc = inet_addr(os.str().c_str());
                uint16_t portdst = 1200 + i;
                uint16_t portsrc = 8080;
                uint16_t proto = 6;

                unsigned long h1 = ipsrc^portsrc^proto^ipdst^portdst;
                unsigned long h2 = ipdst^portdst^proto^ipsrc^portsrc;

                SharedPointer<Flow> f1 = fm->findFlow(h1,h2);

                if(f1) {
                        // The flow only have one packet
                        BOOST_CHECK(f1->total_packets == 1);
                        ++f1->total_packets;
                } else {
                        BOOST_CHECK(1 == 2); // fail
                }
        }
}


BOOST_AUTO_TEST_SUITE_END( )

BOOST_AUTO_TEST_SUITE (flowmanager_time) // test for manage the time 

BOOST_AUTO_TEST_CASE (test1_flowmanager)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        SharedPointer<Flow> f1 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f2 = SharedPointer<Flow>(new Flow());

        f1->setId(1^2^3^4^5);f1->setFiveTuple(1,1000,6,2,80);
	f2->setId(1^2^3^4^6);f2->setFiveTuple(1,1000,6,3,80);

        f1->setArriveTime(0);
        f2->setArriveTime(0);

        fm->addFlow(f1);
        fm->addFlow(f2);
	
	// fm->showFlowsByTime();
	
	fm->updateFlowTime(f1,200);
	fm->updateFlowTime(f2,2);

	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

	// fm->showFlowsByTime();
        // Update the time of the flows
        fm->updateTimers(200);
        BOOST_CHECK(fm->getTotalFlows() == 1);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 1);
	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 1);
}

BOOST_AUTO_TEST_CASE (test2_flowmanager)
{
  	FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
	SharedPointer<Flow> f1 = SharedPointer<Flow>(new Flow());
	SharedPointer<Flow> f2 = SharedPointer<Flow>(new Flow());
	SharedPointer<Flow> f3 = SharedPointer<Flow>(new Flow());

	f1->setId(1^2^3^4^5);f1->setFiveTuple(1,1000,6,2,80);
	f2->setId(1^2^3^4^6);f2->setFiveTuple(1,1000,6,3,80);
	f3->setId(1^2^3^4^7);f3->setFiveTuple(1,1000,6,4,80);

	f1->setArriveTime(0);
	f2->setArriveTime(0);
	f3->setArriveTime(0);

	f1->setLastPacketTime(1);
	f2->setLastPacketTime(2);
	f3->setLastPacketTime(200);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);
 
	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);
	BOOST_CHECK(f3.use_count() == 2);

	BOOST_CHECK(fm->getTotalFlows() == 3);
	BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);	

	fm->updateFlowTime(f1,1);
	fm->updateFlowTime(f2,2);
	fm->updateFlowTime(f3,200);

	// Update the time of the flows
	fm->updateTimers(200);
	BOOST_CHECK(fm->getTotalFlows() == 1);
	BOOST_CHECK(fm->getTotalTimeoutFlows() == 2);	
	
	BOOST_CHECK(f1.use_count() == 1);
	BOOST_CHECK(f2.use_count() == 1);
	BOOST_CHECK(f3.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test3_flowmanager)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        SharedPointer<Flow> f1 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f2 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f3 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f4 = SharedPointer<Flow>(new Flow());

        f1->setId(1^2^3^4^5);f1->setFiveTuple(1,1000,6,2,80);
        f2->setId(1^2^3^4^6);f2->setFiveTuple(1,1000,6,3,80);
        f3->setId(1^2^3^4^7);f3->setFiveTuple(1,1000,6,4,80);
        f4->setId(10^2^3^4^7);f4->setFiveTuple(111,1000,6,4,80);

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);
        f4->setArriveTime(0);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);
        fm->addFlow(f4);

        //fm->showFlowsByTime();
	
        fm->updateFlowTime(f1,1);
        fm->updateFlowTime(f2,200);
        fm->updateFlowTime(f4,210);
        fm->updateFlowTime(f3,2);

        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 2);
        BOOST_CHECK(f4.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 4);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

        //fm->showFlowsByTime();
        // Update the time of the flows
        fm->updateTimers(220);

        //fm->showFlowsByTime();
        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 2);

        BOOST_CHECK(f1.use_count() == 1);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 1);
        BOOST_CHECK(f4.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test4_flowmanager)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        SharedPointer<Flow> f1 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f2 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f3 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f4 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f5 = SharedPointer<Flow>(new Flow());

        f1->setId(1^2^3^4^5);f1->setFiveTuple(1,1000,6,2,80);
        f2->setId(1^2^3^4^6);f2->setFiveTuple(1,1000,6,3,80);
        f3->setId(1^2^3^4^7);f3->setFiveTuple(1,1000,6,4,80);
        f4->setId(10^2^3^4^7);f4->setFiveTuple(111,1000,6,4,80);
        f5->setId(10^20^3^4^7);f5->setFiveTuple(111,13,6,4,80);

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);
        f4->setArriveTime(0);
        f5->setArriveTime(0);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);
        fm->addFlow(f4);
        fm->addFlow(f5);

	// The flows are not sorted on the multi_index
	f1->setLastPacketTime(150);
	f2->setLastPacketTime(110);
	f3->setLastPacketTime(12); // comatose flow
	f4->setLastPacketTime(17); // comatose flow
	f5->setLastPacketTime(140);
        
	// fm->showFlowsByTime();
        // fm->showFlows();
       
	// Just update three flows 
        fm->updateFlowTime(f1,151);
        fm->updateFlowTime(f2,110);
        fm->updateFlowTime(f5,141);

	// fm->showFlowsByTime();
        // fm->showFlows();

        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 2);
        BOOST_CHECK(f4.use_count() == 2);
        BOOST_CHECK(f5.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 5);

        fm->updateTimers(200);

        BOOST_CHECK(fm->getTotalFlows() == 3);

        BOOST_CHECK(f1.use_count() == 2);
        BOOST_CHECK(f2.use_count() == 2);
        BOOST_CHECK(f3.use_count() == 1);
        BOOST_CHECK(f4.use_count() == 1);
        BOOST_CHECK(f5.use_count() == 2);
}

BOOST_AUTO_TEST_CASE (test22_flowmanager)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        SharedPointer<Flow> f1 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f2 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f3 = SharedPointer<Flow>(new Flow());

        f1->setId(1^2^3^4^5);f1->setFiveTuple(1,1000,6,2,80);
        f2->setId(1^2^3^4^6);f2->setFiveTuple(1,1000,6,3,80);
        f3->setId(1^2^3^4^7);f3->setFiveTuple(1,1000,6,4,80);

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);

        f1->setLastPacketTime(10);
        f2->setLastPacketTime(200);
        f3->setLastPacketTime(300);

	fm->setTimeout(120);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);

	BOOST_CHECK(f1.use_count() == 2);
	BOOST_CHECK(f2.use_count() == 2);
	BOOST_CHECK(f3.use_count() == 2);

        BOOST_CHECK(fm->getTotalFlows() == 3);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

        // Update the time of the flows
        fm->updateTimers(301);
        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 1);

	BOOST_CHECK(f1.use_count() == 1);
	BOOST_CHECK(f2.use_count() == 2);
	BOOST_CHECK(f3.use_count() == 2);

	// flow1 should not exist on the fm
	SharedPointer<Flow> fout = fm->findFlow(1^2^3^4^5,5^4^3^2^1);
	
	BOOST_CHECK(fout.use_count() == 0);
	BOOST_CHECK(fout == nullptr);
}

BOOST_AUTO_TEST_CASE (test23_flowmanager)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        SharedPointer<Flow> f1 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f2 = SharedPointer<Flow>(new Flow());
        SharedPointer<Flow> f3 = SharedPointer<Flow>(new Flow());

        f1->setId(1^2^3^4^5);f1->setFiveTuple(1,1000,6,2,80);
        f2->setId(1^2^3^4^6);f2->setFiveTuple(1,1000,6,3,80);
        f3->setId(1^2^3^4^7);f3->setFiveTuple(1,1000,6,4,80);

        f1->setArriveTime(0);
        f2->setArriveTime(0);
        f3->setArriveTime(0);

        f1->setLastPacketTime(100);
        f2->setLastPacketTime(20);
        f3->setLastPacketTime(300);
	
	fm->setTimeout(210);

        fm->addFlow(f1);
        fm->addFlow(f2);
        fm->addFlow(f3);

        BOOST_CHECK(fm->getTotalFlows() == 3);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 0);

        // Update the time of the flows
        fm->updateTimers(301);
        BOOST_CHECK(fm->getTotalFlows() == 2);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 1);

        // flow2 should not exist on the fm
        SharedPointer<Flow> fout = fm->findFlow(1^2^3^4^6,6^4^3^2^1);

        BOOST_CHECK(fout.use_count() == 0);
        BOOST_CHECK(fout == nullptr);
}

BOOST_AUTO_TEST_CASE (test24_flowmanager_with_flowcache_timeout)
{
        FlowManagerPtr fm = FlowManagerPtr(new FlowManager());
        FlowCachePtr fc = FlowCachePtr(new FlowCache());

        fc->createFlows(64);

        for (int i = 0;i< 66; ++i) {
                SharedPointer<Flow> f = fc->acquireFlow();
                if (f) {
                        unsigned long h1 = 1^2^3^4^i;
                        unsigned long h2 = 4^i^3^1^2;
                        f->setId(h1);
			f->setFiveTuple(1,1000,6,2,80+i);
			f->setArriveTime(0);

                        fm->addFlow(f);
                        BOOST_CHECK(fm->getTotalFlows() == i+1);
                }
        }
       
	// 64 flows should exists on the FlowManager 
	BOOST_CHECK(fm->getTotalFlows() == 64);

	fm->setFlowCache(fc);
	fm->setTimeout(50);

	// Update the time of 33 flows
        for (int i = 0;i< 33; ++i) {
                unsigned long h1 = 1^2^3^4^i;
                unsigned long h2 = 4^i^3^1^2;
                SharedPointer<Flow> f = fm->findFlow(h1,h2);
		if (f) {
			fm->updateFlowTime(f,50);
		}
	}

	fm->updateTimers(80);

        // std::cout << "getTotalFlows:" << fm->getTotalFlows() << std::endl;
        // std::cout << "getTotalProcessFlows:" << fm->getTotalProcessFlows() << std::endl;
        // std::cout << "getTotalTimeoutFlows:" << fm->getTotalTimeoutFlows() << std::endl;
        BOOST_CHECK(fm->getTotalFlows() == 33);
        BOOST_CHECK(fm->getTotalProcessFlows() == 64);
        BOOST_CHECK(fm->getTotalTimeoutFlows() == 31);

        BOOST_CHECK(fc->getTotalFlows() == 31);
        BOOST_CHECK(fc->getTotalAcquires() == 64);
        BOOST_CHECK(fc->getTotalReleases() == 31);
        BOOST_CHECK(fc->getTotalFails() == 2);

	//fm->statistics();
	//fc->statistics();	
}

BOOST_AUTO_TEST_SUITE_END( )
