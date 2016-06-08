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
#ifndef SRC_PROTOCOLS_MQTT_MQTTINFO_H_
#define SRC_PROTOCOLS_MQTT_MQTTINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <vector> 
#include "Pointer.h"
#include "StringCache.h"
#include "FlowInfo.h"

namespace aiengine {

class MQTTInfo : public FlowInfo 
{
public:
    	explicit MQTTInfo() { reset(); }
    	virtual ~MQTTInfo() {}

	void reset();
	void serialize(std::ostream& stream); 
	
	void setCommand(int8_t command) { command_ = command; }
	int8_t getCommand() const { return command_; }

	void incClientCommands() { ++total_client_commands_; }
	void incServerCommands() { ++total_server_commands_; }

	int16_t getTotalClientCommands() const { return total_client_commands_; }
	int16_t getTotalServerCommands() const { return total_server_commands_; }

        int32_t getDataChunkLength() const { return data_chunk_length_; }
        void setDataChunkLength(int32_t length) { data_chunk_length_ = length; }

        void setHaveData(bool value) { have_data_ = value; }
        bool getHaveData() const { return have_data_; }

	SharedPointer<StringCache> topic;

	friend std::ostream& operator<< (std::ostream& out, const MQTTInfo& minfo) {

                out << " Cmd(" << (int)minfo.getCommand();
                out << ")Cli(" << minfo.getTotalClientCommands();
                out << ")Ser(" << minfo.getTotalServerCommands() << ") ";

                if (minfo.topic) out << " Topic:" << minfo.topic->getName();

        	return out;
	}

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)
	const char *getTopic() const { return (topic ? topic->getName() : ""); }	
#endif

private:
	bool have_data_;
	int8_t command_;	
	int16_t total_client_commands_;
	int16_t total_server_commands_;
	int32_t data_chunk_length_;
};

} // namespace aiengine

#endif  // SRC_PROTOCOLS_MQTT_MQTTINFO_H_
