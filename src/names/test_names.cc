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
#include "test_names.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE namestest
#endif
#include <boost/test/unit_test.hpp>

using namespace std;

BOOST_AUTO_TEST_SUITE (testnames) 

BOOST_AUTO_TEST_CASE (test1_names)
{
	SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName("one domain","cdn.domain.com"));

	std::cout << domain->getName() << std::endl;
	std::cout << domain->getExpression() << std::endl;
	//SharedPointer<DomainName> domain = SharedPointer<DomainName>(new DomainName());
}

BOOST_AUTO_TEST_SUITE_END( )
