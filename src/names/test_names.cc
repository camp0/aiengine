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
#include "test_names.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE namestest
#endif
#include <boost/test/unit_test.hpp>

//using namespace std;

BOOST_AUTO_TEST_SUITE (testnames) 

BOOST_AUTO_TEST_CASE (test1_names)
{
	SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
	SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName("one domain","com"));
	SharedPointer<DomainName> domain_candidate;

	BOOST_CHECK( dm->getTotalDomains() == 0);

	dm->addDomainName(domain);
	BOOST_CHECK( dm->getTotalDomains() == 1);
	boost::string_ref value("com");

	BOOST_CHECK( dm->getDomainName(value) == domain);
	BOOST_CHECK( domain->getMatchs() == 1);

	// Now we remove the only item
	dm->removeDomainName(domain);
	BOOST_CHECK( dm->getDomainName(value) == nullptr);
	BOOST_CHECK( domain->getMatchs() == 1);
	BOOST_CHECK( dm->getTotalDomains() == 0);
}

BOOST_AUTO_TEST_CASE (test2_names)
{
        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName("one domain","pepe.com"));
        SharedPointer<DomainName> domain_candidate;

        dm->addDomainName(domain);
	boost::string_ref value("pepe.com");

        BOOST_CHECK(dm->getDomainName(value) == domain);
	BOOST_CHECK( domain->getMatchs() == 1);
	value = ".pepe.com";
        BOOST_CHECK(dm->getDomainName(value) == domain);
	BOOST_CHECK( domain->getMatchs() == 2);

	// Now we remove the only item
	dm->removeDomainName(domain);
	BOOST_CHECK( dm->getDomainName(value) == nullptr);
	BOOST_CHECK( domain->getMatchs() == 2);
	BOOST_CHECK( dm->getTotalDomains() == 0);
}

BOOST_AUTO_TEST_CASE (test3_names)
{
        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName("one domain",".aaa.pepe.com"));
        SharedPointer<DomainName> domain_candidate;

        dm->addDomainName(domain);
	boost::string_ref value(".pepe.com");

        BOOST_CHECK(dm->getDomainName(value) == nullptr);
	BOOST_CHECK( domain->getMatchs() == 0);

	value = "jose.com";
        BOOST_CHECK(dm->getDomainName(value) == nullptr);
	BOOST_CHECK( domain->getMatchs() == 0);

	value = ".aaa.pepe.com";
        BOOST_CHECK(dm->getDomainName(value) == domain);
	BOOST_CHECK( domain->getMatchs() == 1);

	value = "pepe.com";
        BOOST_CHECK(dm->getDomainName(value) == nullptr);
	BOOST_CHECK( domain->getMatchs() == 1);
}

BOOST_AUTO_TEST_CASE (test4_names)
{
        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> d1 = SharedPointer<DomainName>(new DomainName("one domain",".aaa.pepe.com"));
        SharedPointer<DomainName> d2 = SharedPointer<DomainName>(new DomainName("one domain",".pepe.com"));
        SharedPointer<DomainName> domain_candidate;

        dm->addDomainName(d1);
        dm->addDomainName(d2);
        boost::string_ref value(".pepe.com");

        BOOST_CHECK(dm->getDomainName(value) == d2);
	BOOST_CHECK( d1->getMatchs() == 0);
	BOOST_CHECK( d2->getMatchs() == 1);

        value = "jose.com";
        BOOST_CHECK(dm->getDomainName(value) == nullptr);
	BOOST_CHECK( d1->getMatchs() == 0);
	BOOST_CHECK( d2->getMatchs() == 1);

        value = ".aaa.pepe.com";
        BOOST_CHECK(dm->getDomainName(value) == d1);
	BOOST_CHECK( d1->getMatchs() == 1);
	BOOST_CHECK( d2->getMatchs() == 1);

        value = "pepe.com";
        BOOST_CHECK(dm->getDomainName(value) == d2);
	BOOST_CHECK( d1->getMatchs() == 1);
	BOOST_CHECK( d2->getMatchs() == 2);
}


BOOST_AUTO_TEST_CASE (test5_names)
{
        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> domain1 = SharedPointer<DomainName>(new DomainName("one domain",".specific.pepe.com"));
        SharedPointer<DomainName> domain2 = SharedPointer<DomainName>(new DomainName("two domain",".cdn.pepe.com"));
        SharedPointer<DomainName> domain3 = SharedPointer<DomainName>(new DomainName("three domain",".specific.jose.es"));
        SharedPointer<DomainName> domain4 = SharedPointer<DomainName>(new DomainName("four domain",".specific.jose.com"));
        SharedPointer<DomainName> domain_candidate;

        dm->addDomainName(domain1);
        dm->addDomainName(domain2);
        dm->addDomainName(domain3);
        dm->addDomainName(domain4);
	boost::string_ref value("ppepe.com");

	// Nothing to match
        domain_candidate = dm->getDomainName(value);
       	BOOST_CHECK(domain_candidate == nullptr); 

	value = ".cdn.pepe.com";
        domain_candidate = dm->getDomainName(value);
       	BOOST_CHECK(domain_candidate == domain2); 
        
	value = ".pepe.com";
	domain_candidate = dm->getDomainName(value);
       	BOOST_CHECK(domain_candidate == nullptr); 

	value = ".pepe.jose.com";
	domain_candidate = dm->getDomainName(value);
       	BOOST_CHECK(domain_candidate == nullptr); 

	value = ".specific.jose.com";
	domain_candidate = dm->getDomainName(value);
       	BOOST_CHECK(domain_candidate == domain4); 

	//cout << *dom_table;
}

BOOST_AUTO_TEST_CASE (test6_names) 
{
	SharedPointer<DomainNameManager> dom_table = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName("Wired Domain",".wired.com"));

	dom_table->addDomainName(domain);
	boost::string_ref check("www.wired.com");

	SharedPointer<DomainName> candidate = dom_table->getDomainName(check);
	BOOST_CHECK(candidate == domain);
	BOOST_CHECK(candidate->getMatchs() == 1);
}

BOOST_AUTO_TEST_CASE (test7_names)
{
        SharedPointer<DomainNameManager> d = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> domain1 = SharedPointer<DomainName>(new DomainName("Wired Domain",".wired.com"));
        SharedPointer<DomainName> domain2 = SharedPointer<DomainName>(new DomainName("Other Domain",".paco.com"));

        d->addDomainName(domain1);
        d->addDomainName(domain2);

	BOOST_CHECK(d->getTotalDomains() == 2);

	boost::string_ref check("www.paco.com");
        SharedPointer<DomainName> candidate = d->getDomainName(check);
        BOOST_CHECK(candidate == domain2);
        BOOST_CHECK(candidate->getMatchs() == 1);

	//std::cout << *d;

	d->removeDomainName(domain2);
	BOOST_CHECK(d->getTotalDomains() == 1);

	// std::cout << *d;

	// no domain for www.paco.com
        candidate = d->getDomainName(check);
        BOOST_CHECK( d->getDomainName(check) == nullptr);

	check = "bu.wired.com";
        candidate = d->getDomainName(check);
        BOOST_CHECK(candidate == domain1);
        BOOST_CHECK(candidate->getMatchs() == 1);
}

BOOST_AUTO_TEST_CASE (test8_names)
{
        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> d1 = SharedPointer<DomainName>(new DomainName("Wired Domain",".wired.com"));
        SharedPointer<DomainName> d2 = SharedPointer<DomainName>(new DomainName("Other Domain",".paco.com"));
        SharedPointer<DomainName> d3 = SharedPointer<DomainName>(new DomainName("Other Domain",".video.wired.com"));
        SharedPointer<DomainName> d4 = SharedPointer<DomainName>(new DomainName("Other Domain",".photo.wired.com"));
        SharedPointer<DomainName> d5 = SharedPointer<DomainName>(new DomainName("Other Domain",".video.paco.com"));
        SharedPointer<DomainName> d6 = SharedPointer<DomainName>(new DomainName("Other Domain",".photo.paco.com"));

        dm->addDomainName(d1);
        dm->addDomainName(d2);
        dm->addDomainName(d3);
        dm->addDomainName(d4);
        dm->addDomainName(d5);
        dm->addDomainName(d6);

	BOOST_CHECK(dm->getTotalDomains() == 6);

	// Check a domain not specific but contained
	boost::string_ref check("www.paco.com");
        SharedPointer<DomainName> can = dm->getDomainName(check);
        BOOST_CHECK(can == d2);
        BOOST_CHECK(can->getMatchs() == 1);

	check = "mark.photo.paco.com";
        can = dm->getDomainName(check);
        BOOST_CHECK(can == d6);
        BOOST_CHECK(can->getMatchs() == 1);

	// std::cout << *dm;
	
	// Now we start to remove and to recheck, remove .photo.wired.com
	dm->removeDomainName(d4);
	BOOST_CHECK(dm->getTotalDomains() == 5);

	// the .photo.wired.com dont not exists, but exists .wired.com
	check = ".photo.wired.com";
        BOOST_CHECK( dm->getDomainName(check) == d1 );

	// Now remove the parent finally
	dm->removeDomainName(d1);
	BOOST_CHECK(dm->getTotalDomains() == 4);
	
	// the .photo.wired.com dont not exists, and .wired.com dont exists also
	check = ".photo.wired.com";
        BOOST_CHECK( dm->getDomainName(check) == nullptr );
	// std::cout << *dm;

	check = ".other.paco.com";
	can = dm->getDomainName(check);
	BOOST_CHECK( can == d2 );	

}

// Test case for remove domains by name
BOOST_AUTO_TEST_CASE (test9_names)
{
        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> d1 = SharedPointer<DomainName>(new DomainName("Wired Domain",".wired.com"));
        SharedPointer<DomainName> d2 = SharedPointer<DomainName>(new DomainName("Other Domain",".paco.com"));
        SharedPointer<DomainName> d3 = SharedPointer<DomainName>(new DomainName("Other Domain",".video.wired.com"));
        SharedPointer<DomainName> d4 = SharedPointer<DomainName>(new DomainName("Other Domain",".photo.wired.com"));
        SharedPointer<DomainName> d5 = SharedPointer<DomainName>(new DomainName("Other Domain",".video.paco.com"));
        SharedPointer<DomainName> d6 = SharedPointer<DomainName>(new DomainName("Other Domain",".photo.paco.com"));
        SharedPointer<DomainName> d7 = SharedPointer<DomainName>(new DomainName("Wired Domain",".aaa.wired.com"));

        dm->addDomainName(d1);
        dm->addDomainName(d2);
        dm->addDomainName(d3);
        dm->addDomainName(d4);
        dm->addDomainName(d5);
        dm->addDomainName(d6);
        dm->addDomainName(d7);

	BOOST_CHECK(dm->getTotalDomains() == 7);
	dm->removeDomainNameByName("nothing");
	BOOST_CHECK(dm->getTotalDomains() == 7);
	dm->removeDomainNameByName("Other Domain");
	BOOST_CHECK(dm->getTotalDomains() == 2);
	dm->removeDomainNameByName("Wired Domain");
	BOOST_CHECK(dm->getTotalDomains() == 0);
}

// Test case for add/remove domains
BOOST_AUTO_TEST_CASE (test10_names)
{
        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> d1 = SharedPointer<DomainName>(new DomainName("Wired Domain",".wired.com"));
        SharedPointer<DomainName> d2 = SharedPointer<DomainName>(new DomainName("Other Domain",".wired.com"));

        dm->addDomainName(d1);
        dm->addDomainName(d2);
	BOOST_CHECK(dm->getTotalDomains() == 1);

	// Nothing to remove
	dm->removeDomainNameByName("Other Domain");
	BOOST_CHECK(dm->getTotalDomains() == 1);

	dm->removeDomainNameByName("Wired Domain");
	BOOST_CHECK(dm->getTotalDomains() == 0);
}

// Test case for add/remove domains with different subdomains
BOOST_AUTO_TEST_CASE (test11_names)
{
        SharedPointer<DomainNameManager> dm = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> d1 = SharedPointer<DomainName>(new DomainName("Domain",".bad.com"));
        SharedPointer<DomainName> d2 = SharedPointer<DomainName>(new DomainName("Domain",".photos.a1.bad.com"));
        SharedPointer<DomainName> d3 = SharedPointer<DomainName>(new DomainName("Domain",".videos.a1.bad.com"));
        SharedPointer<DomainName> d4 = SharedPointer<DomainName>(new DomainName("Domain",".b1.bad.com"));

        dm->addDomainName(d1);
        dm->addDomainName(d2);
        dm->addDomainName(d3);
        dm->addDomainName(d4);
	BOOST_CHECK(dm->getTotalDomains() == 4);

	// Check a domain not specific but contained on .bad.com
	boost::string_ref check("b3.bad.com");
        BOOST_CHECK( dm->getDomainName(check) == d1);

	// Found on d2
	check = "photos.a1.bad.com";
        BOOST_CHECK( dm->getDomainName(check) == d2);

	// Not found but contained on d1	
	check = "photos.ab.bad.com";
        BOOST_CHECK( dm->getDomainName(check) == d1);

	// Not found but contained on .b1.bad.com
	check = "photos.b1.bad.com";
        BOOST_CHECK( dm->getDomainName(check) == d4);
}

BOOST_AUTO_TEST_SUITE_END( )
