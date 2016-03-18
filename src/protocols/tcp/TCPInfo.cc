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
#include "TCPInfo.h"

namespace aiengine {

void TCPInfo::reset() { 
	syn = 0; syn_ack = 0; ack= 0; fin = 0; rst = 0; push= 0; 
	seq_num[0] = 0; 
	seq_num[1] = 0; 
	state_prev = static_cast<int>(TcpState::CLOSED);
	state_curr = static_cast<int>(TcpState::CLOSED);
#if defined(HAVE_TCP_QOS_METRICS)
	last_sample_time = 0;
	last_client_data_time = 0;
	connection_setup_time = 0;
	server_reset_rate = 0;
	application_response_time = 0;
#endif	
}

void TCPInfo::serialize(std::ostream& stream) {

        bool have_item = false;
#ifdef HAVE_FLOW_SERIALIZATION_COMPRESSION 
	stream << ",\"t\":\"" << this << "\"";
#else
	stream << ",\"tcpflags\":\"" << this << "\"";
#endif

#if defined(HAVE_TCP_QOS_METRICS)
//	out << "QoS[ST(" << ti.connection_setup_time << ")RR(" << ti.server_reset_rate << ")";
//	out << "RT(" << ti.application_response_time << ")]";
#endif

}

} // namespace aiengine
