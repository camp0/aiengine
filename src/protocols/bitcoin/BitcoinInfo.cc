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
#include "BitcoinInfo.h"

namespace aiengine {

void BitcoinInfo::reset() {
	total_transactions_ = 0;
	total_blocks_ = 0;
	total_rejects_ = 0;
}

void BitcoinInfo::serialize(std::ostream& stream) {

#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 
        stream << ",\"i\":{";
        stream << "\"t\":" << total_transactions_ << ",";
        stream << "\"b\":" << total_blocks_ << ",";
        stream << "\"r\":" << total_rejects_ << "";
#else
        stream << ",\"info\":{";
        stream << "\"tx\":" << total_transactions_ << ",";
        stream << "\"blocks\":" << total_blocks_ << ",";
        stream << "\"rejects\":" << total_rejects_ << "";
#endif
        stream << "}";
}

} // namespace aiengine  
