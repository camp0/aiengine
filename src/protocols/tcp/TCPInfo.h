/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
#ifndef SRC_PROTOCOLS_TCP_TCPINFO_H_ 
#define SRC_PROTOCOLS_TCP_TCPINFO_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include "TCPStates.h"

namespace aiengine {

class TCPInfo 
{
public:
    	explicit TCPInfo() { reset(); }
    	virtual ~TCPInfo() {}

        void reset() { 
		syn = 0; syn_ack = 0; ack= 0; fin = 0; push= 0; 
		seq_num[0] = 0; 
		seq_num[1] = 0; 
		state_prev = static_cast<int>(TcpState::CLOSED);
		state_curr = static_cast<int>(TcpState::CLOSED);
	}

	// TCP State
        short state_prev;
        short state_curr;

	// TCP Flags
	int16_t syn;
	int16_t syn_ack;
	int16_t ack;
	int16_t fin;
	int16_t push;

	// TCP Sequence numbers 0 for upstream and 1 for downstream FlowDirection
	uint32_t seq_num[2];

        friend std::ostream& operator<< (std::ostream& out, const TCPInfo& ti) {
        
                out << "S(" << ti.syn << ")SA(" << ti.syn_ack << ")A(" << ti.ack;
                out << ")F(" << ti.fin << ")P(" << ti.push << ")Seq(" << ti.seq_num[0] << "," << ti.seq_num[1] << ")";
//		out << ")Ack(" << ti.ack_num << ")";
                return out;
        }
};

} // namespace aiengine
 

#endif  // SRC_PROTOCOLS_TCP_TCPINFO_H_
