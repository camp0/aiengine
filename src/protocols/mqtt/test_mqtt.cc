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
#include "test_mqtt.h"

#define BOOST_TEST_DYN_LINK
#ifdef STAND_ALONE
#define BOOST_TEST_MODULE mqtttest
#endif
#include <boost/test/unit_test.hpp>

using namespace aiengine;

BOOST_FIXTURE_TEST_SUITE(mqtt_suite,StackMQTTtest)

BOOST_AUTO_TEST_CASE (test1_mqtt)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_flow1_mqtt_connect);
        int length = raw_packet_ethernet_ip_tcp_flow1_mqtt_connect_length;
        Packet packet(pkt,length);

	inject(packet);

        BOOST_CHECK(mqtt->getTotalPackets() == 1);
        BOOST_CHECK(mqtt->getTotalValidatedPackets() == 1);
        BOOST_CHECK(mqtt->getTotalBytes() == 77);

	BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));
	BOOST_CHECK(mqtt->getFlags() == 0x00);
	BOOST_CHECK(mqtt->getLength() == 75);

	BOOST_CHECK(mqtt->getTotalClientCommands() == 1);
	BOOST_CHECK(mqtt->getTotalServerCommands() == 0);

        Flow *flow = mqtt->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);
	BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));
}

BOOST_AUTO_TEST_CASE (test2_mqtt)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (&raw_packet_ethernet_ip_tcp_flow1_mqtt_connect[54]);
        int length1 = raw_packet_ethernet_ip_tcp_flow1_mqtt_connect_length - 54;
        Packet packet1(pkt1,length1);
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (&raw_packet_ethernet_ip_tcp_flow1_mqtt_connect_ack[54]);
        int length2 = raw_packet_ethernet_ip_tcp_flow1_mqtt_connect_ack_length - 54;
        Packet packet2(pkt2,length2);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
       	mqtt->processFlow(flow.get());
       
	// some checks on the first packet 
        BOOST_CHECK(mqtt->getTotalPackets() == 1);
        BOOST_CHECK(mqtt->getTotalBytes() == 77);

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 75);

	flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
       	mqtt->processFlow(flow.get());

        BOOST_CHECK(mqtt->getTotalPackets() == 2);
        BOOST_CHECK(mqtt->getTotalBytes() == 77 + 6);

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNACK));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 2);

        BOOST_CHECK(mqtt->getTotalClientCommands() == 1);
        BOOST_CHECK(mqtt->getTotalServerCommands() == 1);

        Flow *curr_flow = mqtt->getCurrentFlow();

        BOOST_CHECK( curr_flow != nullptr);
        SharedPointer<MQTTInfo> info = curr_flow->getMQTTInfo();
        BOOST_CHECK( info != nullptr);
        BOOST_CHECK( info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNACK));
        BOOST_CHECK( info->getTotalClientCommands() == 1);
        BOOST_CHECK( info->getTotalServerCommands() == 1);
}

BOOST_AUTO_TEST_CASE (test3_mqtt) 
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (&raw_packet_ethernet_ip_tcp_flow2_mqtt_subscribe_request[54]);
        int length1 = raw_packet_ethernet_ip_tcp_flow2_mqtt_subscribe_request_length - 54;
        Packet packet1(pkt1,length1);
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (&raw_packet_ethernet_ip_tcp_flow2_mqtt_subscribe_ack[54]);
        int length2 = raw_packet_ethernet_ip_tcp_flow2_mqtt_subscribe_ack_length - 54;
        Packet packet2(pkt2,length2);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
        mqtt->processFlow(flow.get());

        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK( info != nullptr);
        BOOST_CHECK( info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_SUBSCRIBE));

        BOOST_CHECK( info->getTotalClientCommands() == 1);
        BOOST_CHECK( info->getTotalServerCommands() == 0);

        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        mqtt->processFlow(flow.get());

        BOOST_CHECK( info != nullptr);
        BOOST_CHECK( info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_SUBACK));

        BOOST_CHECK( info->getTotalClientCommands() == 1);
        BOOST_CHECK( info->getTotalServerCommands() == 1);
}

BOOST_AUTO_TEST_CASE (test4_mqtt) 
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (&raw_packet_ethernet_ip_tcp_flow2_mqtt_publish_message[54]);
        int length1 = raw_packet_ethernet_ip_tcp_flow2_mqtt_publish_message_length - 54;
        Packet packet1(pkt1,length1);
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (&raw_packet_ethernet_ip_tcp_flow2_mqtt_publish_ack[54]);
        int length2 = raw_packet_ethernet_ip_tcp_flow2_mqtt_publish_ack_length - 54;
        Packet packet2(pkt2,length2);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
        mqtt->processFlow(flow.get());

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(mqtt->getFlags() == 0x02);

        BOOST_CHECK(mqtt->getLength() == 260);

        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK( info != nullptr);
        BOOST_CHECK( info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));

        BOOST_CHECK( info->getTotalClientCommands() == 1);
        BOOST_CHECK( info->getTotalServerCommands() == 0);

        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        mqtt->processFlow(flow.get());

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBACK));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 2);

        BOOST_CHECK( info != nullptr);
        BOOST_CHECK( info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBACK));

        BOOST_CHECK( info->getTotalClientCommands() == 1);
        BOOST_CHECK( info->getTotalServerCommands() == 1);
}

BOOST_AUTO_TEST_CASE (test5_mqtt)
{
        unsigned char *pkt1 = reinterpret_cast <unsigned char*> (&raw_packet_ethernet_ip_tcp_flow2_mqtt_publish_long_pkt1[54]);
        int length1 = raw_packet_ethernet_ip_tcp_flow2_mqtt_publish_long_pkt1_length - 54;
        Packet packet1(pkt1,length1);
        unsigned char *pkt2 = reinterpret_cast <unsigned char*> (&raw_packet_ethernet_ip_tcp_flow2_mqtt_publish_long_pkt2[54]);
        int length2 = raw_packet_ethernet_ip_tcp_flow2_mqtt_publish_long_pkt2_length - 54;
        Packet packet2(pkt2,length2);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet1);
        mqtt->processFlow(flow.get());

	// The first packet have the information and the second is just pure payload
        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(mqtt->getFlags() == 0x02);
        BOOST_CHECK(mqtt->getLength() == 2057);

        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK( info != nullptr);
        BOOST_CHECK( info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK( info->getTotalClientCommands() == 1);
        BOOST_CHECK( info->getTotalServerCommands() == 0);
	BOOST_CHECK( info->getHaveData() == true );
	BOOST_CHECK( info->getDataChunkLength() == 595); // The data left to read

	// This packet just contains data payload
        flow->setFlowDirection(FlowDirection::BACKWARD);
        flow->packet = const_cast<Packet*>(&packet2);
        mqtt->processFlow(flow.get());

	// This are the old values 
        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK(mqtt->getFlags() == 0x02);
        BOOST_CHECK(mqtt->getLength() == 2057);

	// the minfo have change
        BOOST_CHECK( info != nullptr);
        BOOST_CHECK( info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH));
        BOOST_CHECK( info->getTotalClientCommands() == 1);
        BOOST_CHECK( info->getTotalServerCommands() == 0);
	BOOST_CHECK( info->getHaveData() == false );
	BOOST_CHECK( info->getDataChunkLength() == 0); // All the data have been consumed
}

BOOST_AUTO_TEST_CASE (test6_mqtt)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (&raw_packet_ethernet_ip_tcp_flow2_mqtt_disconnect_request[54]);
        int length = raw_packet_ethernet_ip_tcp_flow2_mqtt_disconnect_request_length - 54;
        Packet packet(pkt,length);

        SharedPointer<Flow> flow = SharedPointer<Flow>(new Flow());

        flow->setFlowDirection(FlowDirection::FORWARD);
        flow->packet = const_cast<Packet*>(&packet);
        mqtt->processFlow(flow.get());

        BOOST_CHECK(mqtt->getTotalPackets() == 1);
        BOOST_CHECK(mqtt->getTotalValidatedPackets() == 0);
        BOOST_CHECK(mqtt->getTotalBytes() == 2);

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_DISCONNECT));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 0);
}

BOOST_AUTO_TEST_CASE (test7_mqtt)
{
        unsigned char *pkt = reinterpret_cast <unsigned char*> (raw_packet_ethernet_ip_tcp_flow3_mqtt_connect);
        int length = raw_packet_ethernet_ip_tcp_flow3_mqtt_connect_length;
        Packet packet(pkt,length);

        inject(packet);

        BOOST_CHECK(mqtt->getTotalPackets() == 1);
        BOOST_CHECK(mqtt->getTotalValidatedPackets() == 1);
        BOOST_CHECK(mqtt->getTotalBytes() == 19);

        BOOST_CHECK(mqtt->getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));
        BOOST_CHECK(mqtt->getFlags() == 0x00);
        BOOST_CHECK(mqtt->getLength() == 17);

        BOOST_CHECK(mqtt->getTotalClientCommands() == 1);
        BOOST_CHECK(mqtt->getTotalServerCommands() == 0);

        Flow *flow = mqtt->getCurrentFlow();

        BOOST_CHECK( flow != nullptr);
        SharedPointer<MQTTInfo> info = flow->getMQTTInfo();
        BOOST_CHECK(info != nullptr);
        BOOST_CHECK(info->getCommand() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT));
}

BOOST_AUTO_TEST_SUITE_END()

