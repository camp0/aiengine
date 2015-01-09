/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
#include "RegexManager.h"
#include "Regex.h"
#include "../../test/ipv6_test_packets.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE regextest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_AUTO_TEST_SUITE(regex_suite)

BOOST_AUTO_TEST_CASE (test1_regex)
{
	RegexManagerPtr sigmng = RegexManagerPtr( new RegexManager());

	BOOST_CHECK(sigmng->getTotalRegexs()  ==0);
	BOOST_CHECK(sigmng->getTotalMatchingRegexs() == 0);
	BOOST_CHECK(sigmng->getMatchedRegex() == nullptr);
}

BOOST_AUTO_TEST_CASE (test2_regex)
{
	RegexManagerPtr sigmng = RegexManagerPtr( new RegexManager());

	sigmng->addRegex("hello","^hello.*$");
        BOOST_CHECK(sigmng->getTotalRegexs()  == 1);
        BOOST_CHECK(sigmng->getTotalMatchingRegexs() == 0);
        BOOST_CHECK(sigmng->getMatchedRegex() == nullptr);

	std::string buffer("hello world");
	bool value = false;

	sigmng->evaluate(buffer,&value);
	BOOST_CHECK(value == true);
	BOOST_CHECK(sigmng->getMatchedRegex() != nullptr);
        BOOST_CHECK(sigmng->getTotalMatchingRegexs() == 1);
}

BOOST_AUTO_TEST_CASE (test3_regex)
{
        RegexManagerPtr sigmng = RegexManagerPtr( new RegexManager());
	SharedPointer<Regex> sig = SharedPointer<Regex>( new Regex("name","^.*(some hex).*$"));

        sigmng->addRegex(sig);
        BOOST_CHECK(sigmng->getTotalRegexs()  == 1);
        BOOST_CHECK(sigmng->getTotalMatchingRegexs() == 0);
        BOOST_CHECK(sigmng->getMatchedRegex() == nullptr);

        std::string buffer("hello world im not a hex, but some hex yes");
        bool value = false;

        sigmng->evaluate(buffer,&value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(sigmng->getMatchedRegex() != nullptr);
        BOOST_CHECK(sigmng->getMatchedRegex().get() != nullptr);
        BOOST_CHECK(sigmng->getTotalMatchingRegexs() == 1);

	BOOST_CHECK(sig->getExpression().compare(sigmng->getMatchedRegex()->getExpression())== 0);

}

BOOST_AUTO_TEST_CASE (test4_regex)
{
        RegexManagerPtr sigmng = RegexManagerPtr(new RegexManager());
	SharedPointer<Regex> sig1 = SharedPointer<Regex>(new Regex("name1","^.*(some hex).*$"));
	SharedPointer<Regex> sig2 = SharedPointer<Regex>(new Regex("name2","^.*(some hex).*$"));

	BOOST_CHECK(sig1->isTerminal() == true);
	BOOST_CHECK(sig2->isTerminal() == true);

	sig1->setNextRegex(sig2);

	BOOST_CHECK(sig1->isTerminal() == false);
	BOOST_CHECK(sig2->isTerminal() == true);

	BOOST_CHECK(sig1->getNextRegex() == sig2);

        sigmng->addRegex(sig1);
        sigmng->addRegex(sig2);
	//std::cout << *sigmng;
}

BOOST_AUTO_TEST_CASE (test5_regex)
{
        RegexManagerPtr sigmng = RegexManagerPtr( new RegexManager());
	SharedPointer<Regex> re1 = SharedPointer<Regex>(new Regex("name1","^.*\xaa\xbb\xff\xff.*$"));
	SharedPointer<Regex> re2 = SharedPointer<Regex>(new Regex("name2","^.*\xee$"));
	unsigned char buffer1[] = "\x00\x00\x00\xaa\xbb\xcc\xdd";
	unsigned char buffer2[] = "\x00\x00\x00\xaa\xbb\x00\x00\xcc\xdd";
	unsigned char buffer3[] = "\x00\x00\x00\xaa\xbb\x00\x00\xcc\xdd\xaa\xbb\x00\x00\x00\x00\xff\xff";
	unsigned char buffer4[] = "\x00\x00\x00\xaa\xbb\x00\x00\xcc\xdd\xaa\xaa\xff\xff\x00\x00\xff\xff\xee";
	bool value;

        sigmng->addRegex(re1);
        sigmng->addRegex(re2);

        value = false;
	std::string data1(reinterpret_cast<const char*>(buffer1),6);
        sigmng->evaluate(data1,&value);
        BOOST_CHECK(value == false);
        BOOST_CHECK(sigmng->getMatchedRegex() == nullptr);

	// Check the regex status
	BOOST_CHECK(re1->getMatchs() == 0);
	BOOST_CHECK(re2->getMatchs() == 0);
	BOOST_CHECK(re1->getTotalEvaluates() == 1);
	BOOST_CHECK(re2->getTotalEvaluates() == 1);

	value = false;
	std::string data2(reinterpret_cast<const char*>(buffer2),9);
        sigmng->evaluate(data2,&value);
        BOOST_CHECK(value == false);
        BOOST_CHECK(sigmng->getMatchedRegex() == nullptr);
	
	// Check the regex status
	BOOST_CHECK(re1->getMatchs() == 0);
	BOOST_CHECK(re2->getMatchs() == 0);
	BOOST_CHECK(re1->getTotalEvaluates() == 2);
	BOOST_CHECK(re2->getTotalEvaluates() == 2);

	value = false;
	std::string data3(reinterpret_cast<const char*>(buffer3),17);
        sigmng->evaluate(data3,&value);
        BOOST_CHECK(value == false);
        BOOST_CHECK(sigmng->getMatchedRegex() == nullptr);

	// Check the regex status
	BOOST_CHECK(re1->getMatchs() == 0);
	BOOST_CHECK(re2->getMatchs() == 0);
	BOOST_CHECK(re1->getTotalEvaluates() == 3);
	BOOST_CHECK(re2->getTotalEvaluates() == 3);

	value = false;
	std::string data4(reinterpret_cast<const char*>(buffer4),18);
        sigmng->evaluate(data4,&value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(sigmng->getMatchedRegex() == re2);
	
	// Check the regex status
	BOOST_CHECK(re1->getMatchs() == 0);
	BOOST_CHECK(re2->getMatchs() == 1);
	BOOST_CHECK(re1->getTotalEvaluates() == 4);
	BOOST_CHECK(re2->getTotalEvaluates() == 4);
}

BOOST_AUTO_TEST_CASE (test6_regex)
{
	unsigned char buffer_text[] = 
		"\x69\x74\x73\x20\x70\x65\x61\x6e\x75\x74\x20\x62\x75\x74\x74\x65"
		"\x72\x20\x26\x20\x73\x65\x6d\x65\x6d\x20\x74\x69\x6d\x65\x0a";
        RegexManagerPtr sigmng = RegexManagerPtr( new RegexManager());
	SharedPointer<Regex> re1 = SharedPointer<Regex>(new Regex("r1","^(its peanut).*$"));
	SharedPointer<Regex> re2 = SharedPointer<Regex>(new Regex("r2","^.*(its peanut).*$"));

        sigmng->addRegex(re1);

        bool value = false;
        std::string data1(reinterpret_cast<const char*>(raw_ethernet_ipv6_tcp_text_message),raw_ethernet_ipv6_tcp_text_message_length);
        std::string data2(reinterpret_cast<const char*>(buffer_text),31);

        sigmng->evaluate(data1,&value);
        BOOST_CHECK(value == false);
        BOOST_CHECK(sigmng->getMatchedRegex() == nullptr);

        sigmng->evaluate(data2,&value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(sigmng->getMatchedRegex() == re1);
	
        sigmng->addRegex(re2);
        
	sigmng->evaluate(data1,&value);
        BOOST_CHECK(value == true);
        BOOST_CHECK(sigmng->getMatchedRegex() == re2);
}

BOOST_AUTO_TEST_CASE (test7_regex)
{
	std::string text("GET some/data/i/want/to/retrieve HTTP");
        RegexManagerPtr sigmng = RegexManagerPtr( new RegexManager());
        SharedPointer<Regex> re = SharedPointer<Regex>(new Regex("r1","^GET .* HTTP$"));

	bool value = re->matchAndExtract(text);

	BOOST_CHECK( value == true);
	BOOST_CHECK( text.compare(re->getExtract()) == 0);
}

BOOST_AUTO_TEST_SUITE_END( )

