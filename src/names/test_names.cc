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
	SharedPointer<DomainNameManager> dom_table = SharedPointer<DomainNameManager>(new DomainNameManager());
	SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName("one domain","com"));
	SharedPointer<DomainName> domain_candidate;

	dom_table->addDomainName(domain);

	boost::string_ref value("com");

	domain_candidate = dom_table->getDomainName(value);

	BOOST_CHECK(domain_candidate == domain);
}

BOOST_AUTO_TEST_CASE (test2_names)
{
        SharedPointer<DomainNameManager> dom_table = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName("one domain","pepe.com"));
        SharedPointer<DomainName> domain_candidate;

        dom_table->addDomainName(domain);
	boost::string_ref value("pepe.com");

        domain_candidate = dom_table->getDomainName(value);

        BOOST_CHECK(domain_candidate == domain);
	value = ".pepe.com";
        domain_candidate = dom_table->getDomainName(value);
        BOOST_CHECK(domain_candidate == domain);
}

BOOST_AUTO_TEST_CASE (test3_names)
{
        SharedPointer<DomainNameManager> dom_table = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName("one domain",".specific.pepe.com"));
        SharedPointer<DomainName> domain_candidate;

        dom_table->addDomainName(domain);
	boost::string_ref value("pepe.com");

        domain_candidate = dom_table->getDomainName(value);
        BOOST_CHECK(domain_candidate != domain);
	value = "jose.com";
        domain_candidate = dom_table->getDomainName(value);
	BOOST_CHECK(domain_candidate == nullptr);
}


BOOST_AUTO_TEST_CASE (test4_names)
{
        SharedPointer<DomainNameManager> dom_table = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> domain1 = SharedPointer<DomainName>(new DomainName("one domain",".specific.pepe.com"));
        SharedPointer<DomainName> domain2 = SharedPointer<DomainName>(new DomainName("two domain",".cdn.pepe.com"));
        SharedPointer<DomainName> domain3 = SharedPointer<DomainName>(new DomainName("three domain",".specific.jose.es"));
        SharedPointer<DomainName> domain4 = SharedPointer<DomainName>(new DomainName("four domain",".specific.jose.com"));
        SharedPointer<DomainName> domain_candidate;

        dom_table->addDomainName(domain1);
        dom_table->addDomainName(domain2);
        dom_table->addDomainName(domain3);
        dom_table->addDomainName(domain4);
	boost::string_ref value("ppepe.com");

        domain_candidate = dom_table->getDomainName(value);
       	BOOST_CHECK(domain_candidate == nullptr); 

	value = ".cdn.pepe.com";
        domain_candidate = dom_table->getDomainName(value);
       	BOOST_CHECK(domain_candidate == domain2); 
        
	value = ".pepe.com";
	domain_candidate = dom_table->getDomainName(value);
       	BOOST_CHECK(domain_candidate == nullptr); 

	value = ".pepe.jose.com";
	domain_candidate = dom_table->getDomainName(value);
       	BOOST_CHECK(domain_candidate == nullptr); 

	value = ".specific.jose.com";
	domain_candidate = dom_table->getDomainName(value);
       	BOOST_CHECK(domain_candidate == domain4); 

	//cout << *dom_table;
}

BOOST_AUTO_TEST_CASE (test5_names) 
{
	SharedPointer<DomainNameManager> dom_table = SharedPointer<DomainNameManager>(new DomainNameManager());
        SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName("Wired Domain",".wired.com"));

	dom_table->addDomainName(domain);
	boost::string_ref check("www.wired.com");

	SharedPointer<DomainName> candidate = dom_table->getDomainName(check);
	BOOST_CHECK(candidate == domain);
	BOOST_CHECK(candidate->getMatchs() == 1);
}

BOOST_AUTO_TEST_SUITE_END( )
