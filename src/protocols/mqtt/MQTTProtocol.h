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
#ifndef SRC_PROTOCOLS_MQTT_MQTTPROTOCOL_H_ 
#define SRC_PROTOCOLS_MQTT_MQTTPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif
#include "Protocol.h"
#include "MQTTInfo.h"
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iostream>
#include <cstring>
#include "CacheManager.h"
#include <unordered_map>
#include "names/DomainNameManager.h"
#include "flow/FlowManager.h"

namespace aiengine {

// Minimum MQTT header, for data and signaling
typedef struct {
	uint8_t type;
	uint8_t length;
	u_char data[0];
} __attribute__((packed)) mqtt_hdr;

typedef struct {
	uint8_t pad1;
	uint8_t pad2;
	char proto_name[4];
	uint8_t proto_level;
	uint8_t flags;
	uint16_t keep_alive;
} __attribute__((packed)) mqtt_connect_hdr;

enum class MQTTControlPacketTypes : std::int8_t {
	MQTT_CPT_RESERVED1 = 	0,
	MQTT_CPT_CONNECT ,  	
	MQTT_CPT_CONNACK ,  	
	MQTT_CPT_PUBLISH ,  	
	MQTT_CPT_PUBACK ,  	
	MQTT_CPT_PUBREC ,  	
	MQTT_CPT_PUBREL ,  	
	MQTT_CPT_PUBCOMP ,  	
	MQTT_CPT_SUBSCRIBE ,  	
	MQTT_CPT_SUBACK ,  	
	MQTT_CPT_UNSUBSCRIBE ,  	
	MQTT_CPT_UNSUBACK ,  	
	MQTT_CPT_PINGREQ ,  	
	MQTT_CPT_PINGRESP ,  	
	MQTT_CPT_DISCONNECT ,  	
	MQTT_CPT_RESERVED2  	
};

// Commands with statistics
typedef std::tuple<std::int8_t, const char*,int32_t> MqttControlPacketType;

class MQTTProtocol: public Protocol 
{
public:
    	explicit MQTTProtocol():Protocol("MQTTProtocol","mqtt"),
		stats_level_(0),
		mqtt_header_(nullptr),total_bytes_(0),
		total_mqtt_client_commands_(0),
		total_mqtt_server_responses_(0),
		length_offset_(0),
		info_cache_(new Cache<MQTTInfo>("MQTT Info cache")),
		topic_cache_(new Cache<StringCache>("MQTT Topic cache")),
		topic_map_(),
		flow_mng_(),
		current_flow_(nullptr),
		anomaly_(),
		cache_mng_() {}

    	virtual ~MQTTProtocol() { anomaly_.reset(); cache_mng_.reset(); }

	static const uint16_t id = 0;
	static const int header_size = sizeof(mqtt_hdr); 
	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_; }
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

	bool processPacket(Packet& packet) { return true; }
	void processFlow(Flow *flow);

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache(); 

        void setHeader(unsigned char *raw_packet) {
                
		mqtt_header_ = reinterpret_cast<mqtt_hdr*>(raw_packet);
        }

	// Condition for say that a payload is MQTT 
	bool mqttChecker(Packet &packet) { 

                int length = packet.getLength();

                if(length >= header_size) {
			unsigned char *payload = packet.getPayload();
                        setHeader(payload);
			if (getCommandType() == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT)) {
				if (length >= header_size + sizeof(mqtt_connect_hdr)) {
					mqtt_connect_hdr *conn_hdr = reinterpret_cast<mqtt_connect_hdr*>(&payload[header_size]);
					// std::cout << "token:" << conn_hdr->proto_name << std::endl;	
					if (std::memcmp(&conn_hdr->proto_name,"MQ",2) == 0) {
                                		++total_validated_packets_;
                                		return true;
					}
				}
                        }
                }
		++total_malformed_packets_;
		return false;
	}

	int8_t getCommandType() const { return mqtt_header_->type >> 4; }
	uint8_t getFlags() const { return mqtt_header_->type & 0x0F; }
	int32_t getLength(); 

	int32_t getTotalClientCommands() const { return total_mqtt_client_commands_; }
	int32_t getTotalServerCommands() const { return total_mqtt_server_responses_; }

        void increaseAllocatedMemory(int value); 
        void decreaseAllocatedMemory(int value); 

	void setFlowManager(FlowManagerPtrWeak flow_mng) { flow_mng_ = flow_mng; }

	int64_t getAllocatedMemory() const;

	Flow *getCurrentFlow() const { return current_flow_; }

#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
        VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const  { JavaCounters counters; return counters; }
#endif
	void setAnomalyManager(SharedPointer<AnomalyManager> amng) { anomaly_ = amng; }
	void setCacheManager(SharedPointer<CacheManager> cmng) { cache_mng_ = cmng; cache_mng_->setCache(info_cache_); }
private:
	void release_mqtt_info_cache(MQTTInfo *info);
	int32_t release_mqtt_info(MQTTInfo *info);

	void attach_topic(MQTTInfo *info, boost::string_ref &topic);
	void handle_publish_message(MQTTInfo *info, unsigned char *payload, int length);

	int stats_level_;
	mqtt_hdr *mqtt_header_;
        int64_t total_bytes_;

	static std::vector<MqttControlPacketType> commands_;
	
	int32_t total_mqtt_client_commands_;
	int32_t total_mqtt_server_responses_;

	int8_t length_offset_;

        Cache<MQTTInfo>::CachePtr info_cache_;
        Cache<StringCache>::CachePtr topic_cache_;

	GenericMapType topic_map_;

	FlowManagerPtrWeak flow_mng_;
	Flow *current_flow_;	
#ifdef HAVE_LIBLOG4CXX
	static log4cxx::LoggerPtr logger;
#endif
	SharedPointer<AnomalyManager> anomaly_;
	SharedPointer<CacheManager> cache_mng_;
};

typedef std::shared_ptr<MQTTProtocol> MQTTProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_MQTT_MQTTPROTOCOL_H_
