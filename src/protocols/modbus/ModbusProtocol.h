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
#ifndef SRC_PROTOCOLS_MODBUS_MODBUSPROTOCOL_H_
#define SRC_PROTOCOLS_MODBUS_MODBUSPROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "Protocol.h"
#include <arpa/inet.h>

namespace aiengine {

struct modbus_tcphdr {
	uint16_t 	op;		/* Transaction id */
	uint16_t 	proto;		/* Protocol id */
	uint16_t 	length;		/* Transaction id */
	uint8_t 	unitid;		/* Unit id */
	u_char 		data[0];
} __attribute__((packed));

struct modbus_hdr {
        uint8_t       	code;           /* Function code */
        uint16_t       	proto;          /* Ref number */
	u_char 		data[0];
} __attribute__((packed));

enum modbus_type_function_code {
	MB_CODE_READ_COILS = 1,
	MB_CODE_READ_DISCRETE_INPUTS = 2,
	MB_CODE_READ_HOLDING_REGISTERS = 3,
	MB_CODE_READ_INPUT_REGISTERS = 4,
	MB_CODE_WRITE_SINGLE_COIL = 5,
	MB_CODE_WRITE_SINGLE_REGISTER = 6,
	MB_CODE_WRITE_MULTIPLE_COILS = 15,
	MB_CODE_WRITE_MULTIPLE_REGISTERS = 16
};

class ModbusProtocol: public Protocol 
{
public:
    	explicit ModbusProtocol():
		Protocol("ModbusProtocol","modbus"),
		stats_level_(0),
		modbus_header_(nullptr),total_bytes_(0),
        	total_read_coils_(0),
        	total_read_discrete_inputs_(0),
        	total_read_holding_registers_(0),
        	total_read_input_registers_(0),
        	total_write_single_coil_(0),
        	total_write_single_register_(0),
        	total_write_multiple_coils_(0),
        	total_write_multiple_registers_(0),
        	total_others_(0)
	{}

    	virtual ~ModbusProtocol() {}

	static const uint16_t id = 0;	
	static constexpr int header_size = sizeof(struct modbus_tcphdr);

	int getHeaderSize() const { return header_size;}

	int64_t getTotalBytes() const { return total_bytes_;}
	int64_t getTotalPackets() const { return total_packets_;}
	int64_t getTotalValidatedPackets() const { return total_validated_packets_;}
	int64_t getTotalMalformedPackets() const { return total_malformed_packets_;}

        void processFlow(Flow *flow);
        bool processPacket(Packet& packet) { return true; } 

	void setStatisticsLevel(int level) { stats_level_ = level;}
	void statistics(std::basic_ostream<char>& out);
	void statistics() { statistics(std::cout);}

	void releaseCache() {} // No need to free cache

	void setHeader(unsigned char *raw_packet){ 

		modbus_header_ = reinterpret_cast <struct modbus_tcphdr*> (raw_packet);
	}

	// Condition for say that a packet is dhcp 
	bool modbusChecker(Packet &packet){ 
	
		int length = packet.getLength();

		if(length >= header_size) {
			if ((packet.getSourcePort() == 502)||(packet.getDestinationPort() == 502)) {
				setHeader(packet.getPayload());
				++total_validated_packets_; 
				return true;
			}
		}
		++total_malformed_packets_;
		return false;
	}

	int64_t getAllocatedMemory() const { return sizeof(ModbusProtocol); }
	
#if defined(PYTHON_BINDING)
        boost::python::dict getCounters() const;
#elif defined(RUBY_BINDING)
	VALUE getCounters() const;
#elif defined(JAVA_BINDING)
        JavaCounters getCounters() const ; 
#endif

private:
	int stats_level_;
	struct modbus_tcphdr *modbus_header_;
	int64_t total_bytes_;

	// Some statistics 
	int32_t total_read_coils_;
	int32_t total_read_discrete_inputs_;
	int32_t total_read_holding_registers_;
	int32_t total_read_input_registers_;
	int32_t total_write_single_coil_;
	int32_t total_write_single_register_;
	int32_t total_write_multiple_coils_;
	int32_t total_write_multiple_registers_;
	int32_t total_others_;
};

typedef std::shared_ptr<ModbusProtocol> ModbusProtocolPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_MODBUS_MODBUSPROTOCOL_H_
