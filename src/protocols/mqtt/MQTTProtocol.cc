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

int32_t MQTTProtocol::getLength() const { 

	// Specific way of manage the lengths
	if (mqtt_header_->length >= 0x80) {
		int8_t tok = mqtt_header_->data[0];
		if ((tok & 0x80) == 0) { // For two bytes
			int8_t val = (mqtt_header_->length & 0x7f); 
			int16_t value = val + (128 * tok); 
			return value;	
		}	
	} else {
		return mqtt_header_->length;
	}
	return 0;
}


int64_t MQTTProtocol::getAllocatedMemory() const {

        int64_t value = 0;

        value = sizeof(MQTTProtocol);
        value += info_cache_->getAllocatedMemory();

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

                for (auto &flow: ft) {
                       	SharedPointer<MQTTInfo> sinfo = flow->getMQTTInfo();
			if (sinfo) {
                                total_bytes_released_by_flows += sizeof(sinfo);
                               
                                flow->layer7info.reset();
                                ++ release_flows;
                                info_cache_->release(sinfo);
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
				if (getLength() > length - header_size) {
					minfo->setDataChunkLength(getLength() - (length + header_size));
					minfo->setHaveData(true);
				}
			} else { // Server side
				++ total_mqtt_server_responses_;
				minfo->incServerCommands();
			}
		}
	}
	
	return;
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
                                }
			}
		}
	}
}


void MQTTProtocol::increaseAllocatedMemory(int value) { 

	info_cache_->create(value);
}

void MQTTProtocol::decreaseAllocatedMemory(int value) { 

	info_cache_->destroy(value);
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

