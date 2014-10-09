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
#ifndef SRC_GPRS_GPRSINFO_H_ 
#define SRC_GPRS_GPRSINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>

namespace aiengine {

#define PDP_END_USER_TYPE_IPV4 0x21
#define PDP_END_USER_TYPE_IPV6 0x57

class GPRSInfo 
{
public:
    	explicit GPRSInfo() { reset(); }
    	virtual ~GPRSInfo() {}

        void reset() { 
		imsi_ = 0;
		imei_ = 0;
		pdp_type_number_ = 0; // The upper protocol
	}

	void setPdpTypeNumber(uint8_t type) { pdp_type_number_ = type; }
	uint8_t getPdpTypeNumber() const { return pdp_type_number_; }
	void setIMSI(uint64_t imsi) { imsi_ = imsi; }
	uint64_t getIMSI() const { return imsi_; }

	std::string& getIMSIString() const { 
		std::ostringstream o;
		static std::string cad;
		uint8_t bcd;
		uint8_t *data = (uint8_t*)&imsi_;

		for(int i = 0; i < 8; ++i ) {
			bcd = *data & 0xf;
			if (bcd != 0xf) o << (int)bcd;
			bcd = *data >> 4;
			if (bcd != 0xf) o << (int) bcd; 
			data++;
		}
			
		cad = o.str();
		return cad;
	}

	//uint64_t getIMEI() const { return imei; }

        friend std::ostream& operator<< (std::ostream& out, const GPRSInfo& gi) {
        
                out << "IMSI(" << gi.getIMSIString() << ")";
		if (gi.pdp_type_number_ == PDP_END_USER_TYPE_IPV4) out << "IPv4";
		if (gi.pdp_type_number_ == PDP_END_USER_TYPE_IPV6) out << "IPv6";
                return out;
        }
private:
	uint64_t imsi_;
	uint64_t imei_;
	uint8_t pdp_type_number_;
};

} // namespace aiengine
 

#endif  // SRC_GPRS_GPRSINFO_H_
