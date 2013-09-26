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
#include "SignatureManager.h"
#include "Signature.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE signaturetest
#endif
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE(signature_suite)

BOOST_AUTO_TEST_CASE (test1_signature)
{
	SignatureManagerPtr sigmng = SignatureManagerPtr( new SignatureManager());

	BOOST_CHECK(sigmng->getTotalSignatures()  ==0);
	BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 0);
	BOOST_CHECK(sigmng->getMatchedSignature() == nullptr);
}

BOOST_AUTO_TEST_CASE (test2_signature)
{
	SignatureManagerPtr sigmng = SignatureManagerPtr( new SignatureManager());

	sigmng->addSignature("hello","^hello");
        BOOST_CHECK(sigmng->getTotalSignatures()  == 1);
        BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 0);
        BOOST_CHECK(sigmng->getMatchedSignature() == nullptr);

	std::string cad("hello world");
	bool value = false;
	unsigned const char *buffer = reinterpret_cast<const unsigned char*>(cad.c_str());

	sigmng->evaluate(buffer,&value);
	BOOST_CHECK(value == true);
	BOOST_CHECK(sigmng->getMatchedSignature() != nullptr);
        BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 1);
}

BOOST_AUTO_TEST_CASE (test3_signature)
{
        SignatureManagerPtr sigmng = SignatureManagerPtr( new SignatureManager());
	Signature sig("name","some hex");

        sigmng->addSignature(sig);
        BOOST_CHECK(sigmng->getTotalSignatures()  == 1);
        BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 0);
        BOOST_CHECK(sigmng->getMatchedSignature() == nullptr);

        std::string cad("hello world im not a hex, but some hex yes");
        bool value = false;
        unsigned const char *buffer = reinterpret_cast<const unsigned char*>(cad.c_str());

        sigmng->evaluate(buffer,&value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(sigmng->getMatchedSignature() != nullptr);
        BOOST_CHECK(sigmng->getMatchedSignature().get() != nullptr);
        BOOST_CHECK(sigmng->getTotalMatchingSignatures() == 1);

	// Shared ptr and sig are stored on different places but should have the same regex
	BOOST_CHECK(sig.getExpression().compare(sigmng->getMatchedSignature()->getExpression())== 0);

	//BOOST_CHECK(sig == &sigmng->getMatchedSignature().get()); 
	//std::cout << *sigmng;
}


BOOST_AUTO_TEST_SUITE_END( )

