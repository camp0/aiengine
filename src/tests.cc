#include <string>
#include "Multiplexer.h"

#define BOOST_TEST_DYN_LINK
#define BOOST_TEST_MODULE maintests 
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_SUITE (test1) // name of the test suite is stringtest

BOOST_AUTO_TEST_CASE (test1)
{
	MultiplexerPtr m1 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m2 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m3 = MultiplexerPtr(new Multiplexer());
	MultiplexerPtr m4 = MultiplexerPtr(new Multiplexer());

	BOOST_CHECK(m1->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m2->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m3->getNumberUpMultiplexers()== 0);
	BOOST_CHECK(m4->getNumberUpMultiplexers()== 0);

	BOOST_CHECK(m1->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m2->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m3->getDownMultiplexer().use_count() == 0);
	BOOST_CHECK(m4->getDownMultiplexer().use_count() == 0);

	m1->addDownMultiplexer(m2);
	m1->addUpMultiplexer(m3,1);	
	m1->addUpMultiplexer(m4,2);	
	BOOST_CHECK(m1->getNumberUpMultiplexers()== 2);
}

BOOST_AUTO_TEST_SUITE_END( )

