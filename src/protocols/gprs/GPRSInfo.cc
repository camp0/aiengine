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
#include "GPRSInfo.h"

namespace aiengine {

void GPRSInfo::reset() { 
	imsi_ = 0;
	imei_ = 0;
	pdp_type_number_ = 0; // The upper protocol
}

void GPRSInfo::serialize(std::ostream& stream) {


}

std::string& GPRSInfo::getIMSIString() const { 
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

} // namespace aiengine
