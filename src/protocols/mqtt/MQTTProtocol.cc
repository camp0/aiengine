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
#include "MQTTProtocol.h"
#include <iomanip> // setw

namespace aiengine {

#ifdef HAVE_LIBLOG4CXX
log4cxx::LoggerPtr MQTTProtocol::logger(log4cxx::Logger::getLogger("aiengine.mqtt"));
#endif

// List of support operations
std::vector<MqttControlPacketType> MQTTProtocol::commands_ {
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_RESERVED1),	"Reserved",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNECT),		"Connect",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_CONNACK),		"ConnectAck",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH),		"Publish",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBACK),		"PublishAck",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBREC),		"PublishRec",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBREL),		"PublishRel",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBCOMP),		"PublishComp",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_SUBSCRIBE),	"Subscribe",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_SUBACK),		"SubscribeAck",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_UNSUBSCRIBE),	"Unsubscribe",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_UNSUBACK),		"UnsubscribeAck",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PINGREQ),		"PingReq",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PINGRESP),		"PingRes",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_DISCONNECT),	"Disconnect",	0),
	std::make_tuple(static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_RESERVED2),	"Reserved",	0)
};

int32_t MQTTProtocol::getLength() { 

	// Specific way of manage the lengths
	if (mqtt_header_->length >= 0x80) {
		int8_t tok = mqtt_header_->data[0];
		if ((tok & 0x80) == 0) { // For two bytes
			int8_t val = (mqtt_header_->length & 0x7f); 
			int16_t value = val + (128 * tok); 
			length_offset_ = 2;
			return value;	
		}	
	} else {
		length_offset_ = 1;
		return mqtt_header_->length;
	}
	length_offset_ = 0;
	return 0;
}


int64_t MQTTProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(MQTTProtocol);
        value += info_cache_->getAllocatedMemory();
        value += topic_cache_->getAllocatedMemory();

        return value;
}

void MQTTProtocol::releaseCache() {

	FlowManagerPtr fm = flow_mng_.lock();

	if (fm) {
		auto ft = fm->getFlowTable();

		std::ostringstream msg;
        	msg << "Releasing " << getName() << " cache";

		infoMessage(msg.str());

		int64_t total_bytes_released = 0;
		int64_t total_bytes_released_by_flows = 0;
		int32_t release_flows = 0;

                std::for_each (topic_map_.begin(), topic_map_.end(), [&total_bytes_released] (PairStringCacheHits const &f) {
                        total_bytes_released += f.first.size();
                });

                for (auto &flow: ft) {
                       	SharedPointer<MQTTInfo> minfo = flow->getMQTTInfo();
			if (minfo) {
                                SharedPointer<StringCache> sc = minfo->topic;
                                if (sc) {
                                        minfo->topic.reset();
                                        total_bytes_released_by_flows += sc->getNameSize();
                                        topic_cache_->release(sc);
                                }
                                total_bytes_released_by_flows += sizeof(minfo);
                               
                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(minfo);
                        }
                }

                double cache_compression_rate = 0;

                if (total_bytes_released_by_flows > 0 ) {
                        cache_compression_rate = 100 - ((total_bytes_released*100)/total_bytes_released_by_flows);
                }

                msg.str("");
                msg << "Release " << release_flows << " flows";
                msg << ", " << total_bytes_released << " bytes, compression rate " << cache_compression_rate << "%";
                infoMessage(msg.str());
	}
}

void MQTTProtocol::processFlow(Flow *flow) {

	int length = flow->packet->getLength();
	unsigned char *payload = flow->packet->getPayload();
	total_bytes_ += length;
	++total_packets_;

       	SharedPointer<MQTTInfo> minfo = flow->getMQTTInfo();

       	if(!minfo) {
               	minfo = info_cache_->acquire();
               	if (!minfo) {
                       	return;
               	}
        	flow->layer7info = minfo;
	}

	current_flow_ = flow;

	if (minfo->getHaveData() == true) {
		int32_t left_length = minfo->getDataChunkLength() - length;
		if (left_length > 0) {
			minfo->setDataChunkLength(left_length);
		} else {
			minfo->setDataChunkLength(0);
			minfo->setHaveData(false);
		}
		return;
	}
                
	if (length >= header_size) {
		setHeader(payload);

		int8_t type = (int)getCommandType();
		if ((type > static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_RESERVED1))
			and(type < static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_RESERVED2))) {
				
			auto &command = commands_[type];

			int32_t *hits = &std::get<2>(command);
                        ++(*hits);
			minfo->setCommand(type);

			if (flow->getFlowDirection() == FlowDirection::FORWARD) { // client side
				++total_mqtt_client_commands_;
				minfo->incClientCommands();

				// The getLength also update the header_size with the variable length_offset_
				if (getLength() > length - header_size) {
					minfo->setDataChunkLength(getLength() - (length + header_size));
					minfo->setHaveData(true);
				}

				// The message publish message contains the topic and the information
				if (type == static_cast<int8_t>(MQTTControlPacketTypes::MQTT_CPT_PUBLISH)) {
					handle_publish_message(minfo.get(),&payload[header_size],length - header_size);
				}
			} else { // Server side
				++ total_mqtt_server_responses_;
				minfo->incServerCommands();
			}
		}
	}
	
	return;
} 

void MQTTProtocol::handle_publish_message(MQTTInfo *info, unsigned char *payload, int length) {

	int16_t msglen = 0;
//	std::cout << "Hex0: "<<  (int)payload[1] << " Hex1:" << (int)payload[2] << " lenght_offset:" << (int)length_offset_ << std::endl;
	if (length_offset_ == 2) {
		msglen = ntohs((payload[2] << 8) + payload[1]);
	} else {
		msglen = payload[1];
//		std::cout << "yes" << std::endl;
	}

//	std::cout << "msglen=" << msglen << std::endl;
	//int16_t msglen = ntohs(payload[2] + payload[1]);
//	int16_t msglen = ntohs((payload[length_offset_] << 8) + payload[length_offset_-1]);
	if (msglen < length) {
		boost::string_ref topic((char*)&payload[length_offset_ + 1],msglen);

		attach_topic(info,topic);
//		std::cout << "The topic is:" << topic << std::endl;
	} else {
//		std::cout << "anomaly" << std::endl;
                if (current_flow_->getPacketAnomaly() == PacketAnomalyType::NONE) {
                        current_flow_->setPacketAnomaly(PacketAnomalyType::MQTT_BOGUS_HEADER);
                }
                anomaly_->incAnomaly(PacketAnomalyType::MQTT_BOGUS_HEADER);
	}
}

void MQTTProtocol::attach_topic(MQTTInfo *info, boost::string_ref &topic) {

        if (!info->topic) {
                GenericMapType::iterator it = topic_map_.find(topic);
                if (it == topic_map_.end()) {
                        SharedPointer<StringCache> topic_ptr = topic_cache_->acquire();
                        if (topic_ptr) {
                                topic_ptr->setName(topic.data(),topic.size());
                                info->topic = topic_ptr;
                                topic_map_.insert(std::make_pair(boost::string_ref(topic_ptr->getName()),
                                        std::make_pair(topic_ptr,1)));
                        }
                } else {
                        int *counter = &std::get<1>(it->second);
                        ++(*counter);
                        info->topic = std::get<0>(it->second);
                }
        }
}

void MQTTProtocol::statistics(std::basic_ostream<char>& out)
{
	if (stats_level_ > 0) {
                int alloc_memory = getAllocatedMemory();
                std::string unit = "Bytes";

                unitConverter(alloc_memory,unit);

                out << getName() << "(" << this <<") statistics" << std::dec << std::endl;

                out << "\t" << "Total allocated:        " << std::setw(9 - unit.length()) << alloc_memory << " " << unit <<std::endl;
        	out << "\t" << "Total packets:          " << std::setw(10) << total_packets_ <<std::endl;
        	out << "\t" << "Total bytes:            " << std::setw(10) << total_bytes_ <<std::endl;
		if (stats_level_ > 1) {
		
			out << "\t" << "Total validated packets:" << std::setw(10) << total_validated_packets_ <<std::endl;
			out << "\t" << "Total malformed packets:" << std::setw(10) << total_malformed_packets_ <<std::endl;
                        if(stats_level_ > 3) {

                                out << "\t" << "Total client commands:  " << std::setw(10) << total_mqtt_client_commands_ <<std::endl;
                                out << "\t" << "Total server responses: " << std::setw(10) << total_mqtt_server_responses_ <<std::endl;

                                for (auto &command: commands_) {
                                        const char *label = std::get<1>(command);
                                        int32_t hits = std::get<2>(command);
                                        out << "\t" << "Total " << label << ":" << std::right << std::setfill(' ') << std::setw(27 - strlen(label)) << hits <<std::endl;
                                }
                        }
	
			if (stats_level_ > 2) {	
			
				if (flow_forwarder_.lock())
					flow_forwarder_.lock()->statistics(out);
                                if (stats_level_ > 3) {
                                        info_cache_->statistics(out);
                                        topic_cache_->statistics(out);
                                        if(stats_level_ > 4) {
                                                showCacheMap(out,topic_map_,"MQTT Topics","Topic");
                                        }
                                }
			}
		}
	}
}


void MQTTProtocol::increaseAllocatedMemory(int value) { 

	info_cache_->create(value);
	topic_cache_->create(value);
}

void MQTTProtocol::decreaseAllocatedMemory(int value) { 

	info_cache_->destroy(value);
	topic_cache_->destroy(value);
}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING)
#if defined(PYTHON_BINDING)
boost::python::dict MQTTProtocol::getCounters() const {
        boost::python::dict counters;
#elif defined(RUBY_BINDING)
VALUE MQTTProtocol::getCounters() const {
        VALUE counters = rb_hash_new();
#endif
        addValueToCounter(counters,"packets", total_packets_);
        addValueToCounter(counters,"bytes", total_bytes_);
        addValueToCounter(counters,"commands", total_mqtt_client_commands_);
        addValueToCounter(counters,"responses", total_mqtt_server_responses_);

        for (auto &command: commands_) {
                const char *label = std::get<1>(command);

                addValueToCounter(counters,label,std::get<2>(command));
        }
        return counters;
}

#endif

} // namespace aiengine

