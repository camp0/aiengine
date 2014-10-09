/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#include "test_learner.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE learnertest
#endif
#include <boost/test/unit_test.hpp>

BOOST_AUTO_TEST_CASE (test1_learner)
{
	LearnerEnginePtr le = LearnerEnginePtr(new LearnerEngine());
	SharedPointer<PacketFrequencies> pkt_f1 = SharedPointer<PacketFrequencies>(new PacketFrequencies());

	unsigned char payload1[] = "\x16\x02\xaa\xaa";
	std::string data1(reinterpret_cast<const char*>(payload1),4);
	
	pkt_f1->addPayload(data1);

	for (int i = 0;i< 10;++i)
	{
		le->agregatePacketFlow(pkt_f1);
	}

	BOOST_CHECK(le->getQualityByte(0) == 100);
	BOOST_CHECK(le->getQualityByte(1) == 100);
	BOOST_CHECK(le->getQualityByte(2) == 100);
	BOOST_CHECK(le->getQualityByte(3) == 100);
	BOOST_CHECK(le->getQualityByte(-1) == 0);
	BOOST_CHECK(le->getQualityByte(5000) == 0);
	
	unsigned char payload2[] = "\x16\x02\xaa\x00";
	std::string data2(reinterpret_cast<const char*>(payload2),4);
	SharedPointer<PacketFrequencies> pkt_f2 = SharedPointer<PacketFrequencies>(new PacketFrequencies());

	pkt_f2->addPayload(data2);

        for (int i = 0;i< 10;++i)
        {
                le->agregatePacketFlow(pkt_f2);
        }

	BOOST_CHECK(le->getQualityByte(0) == 100);
	BOOST_CHECK(le->getQualityByte(1) == 100);
	BOOST_CHECK(le->getQualityByte(2) == 100);
	BOOST_CHECK(le->getQualityByte(3) == 95);
	
	le->compute();

	std::string cadena("^\\x16\\x02\\xaa\\x00");

	//std::cout << "regular:" << le->getRegularExpression() << std::endl;
	BOOST_CHECK(cadena.compare(le->getRegularExpression()) == 0);
}


BOOST_AUTO_TEST_CASE (test2_learner)
{
        LearnerEnginePtr le = LearnerEnginePtr(new LearnerEngine());
        SharedPointer<PacketFrequencies> pkt_f1 = SharedPointer<PacketFrequencies>(new PacketFrequencies());

        unsigned char payload1[] = "\xaa\xaa\x01\x02\xff\xff";
	std::string data1(reinterpret_cast<const char*>(payload1),6);

        pkt_f1->addPayload(data1);
        le->agregatePacketFlow(pkt_f1);

        unsigned char payload2[] = "\x16\xaa\xaa\x00";
	std::string data2(reinterpret_cast<const char*>(payload2),4);
        SharedPointer<PacketFrequencies> pkt_f2 = SharedPointer<PacketFrequencies>(new PacketFrequencies());

        pkt_f2->addPayload(data2);

        le->agregatePacketFlow(pkt_f2);

        le->compute();

        std::string cadena("^.?\\xaa.?.?\\xff\\xff");

        BOOST_CHECK(cadena.compare(le->getRegularExpression()) == 0);
}

//BOOST_AUTO_TEST_SUITE_END( )

