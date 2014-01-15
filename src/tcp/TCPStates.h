/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#ifndef SRC_TCP_TCPSTATES_H_
#define SRC_TCP_TCPSTATES_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <cstdint>
#include "../flow/Flow.h"

namespace aiengine {

enum class TcpState : std::int32_t {
	OK 		= (-1),
	CLOSED		= 0, 
	SYN_SENT	= 1,        
	SIMSYN_SENT	= 2, 
	SYN_RECEIVED	= 3, 
	ESTABLISHED	= 4,    
	FIN_SEEN	= 5,         
	CLOSE_WAIT	= 6, 
	FIN_WAIT	= 7,         
	CLOSING		= 8,          
	LAST_ACK	= 9,         
	TIME_WAIT	= 10,      
	MAX_STATES 	= 11   
};

enum class TcpFlags : std::int32_t {
	INVALID = 0,
	SYN	= 1,
	SYNACK 	= 2,
	ACK	= 3,
	FIN	= 4,
	MAX_FLAGS = 5
};

struct ST_TcpFlags {
	int flags[static_cast<int>(TcpFlags::MAX_FLAGS)];
};

struct TCPState {
	char *name;
	struct ST_TcpFlags dir[2]; // 0 for FORWARD, 1 for BACKWARD
};

static struct TCPState ST_NullState = {
	(char*)"NONE",
 	{{ 	/* INVALID */ 	0,
		/* SYN */	0,
		/* SYNACK */	0,
		/* ACK */	0,
		/* FIN */	0
	},
 	{ 	/* INVALID */ 	0,
		/* SYN */	0,
		/* SYNACK */	0,
		/* ACK */	0,
		/* FIN */	0
	}}
};

static struct TCPState ST_TCPStateClosed = {
	(char*)"CLOSE",
 	{{ 	/* INVALID */ 	0,
		/* SYN */	static_cast<int>(TcpState::SYN_SENT), /* Handshake (1): initial SYN. */
		/* SYNACK */	0,
		/* ACK */	0,
		/* FIN */	0	
	},
 	{ 	/* INVALID */ 	0,
		/* SYN */	0,
		/* SYNACK */	0,
		/* ACK */	0,
		/* FIN */	0
        }}
};

static struct TCPState ST_TCPStateSynSent = {
	(char*)"SYN_SENT",
        {{	/* INVALID */	0,
                /* SYN */	static_cast<int>(TcpState::OK), /* SYN may be retransmitted. */
                /* SYNACK */	0,
                /* ACK */	0,
                /* FIN */	0
        },
        {       /* INVALID */	0,
                /* SYN */	static_cast<int>(TcpState::SIMSYN_SENT), /* Simultaneous initiation - SYN. */
                /* SYNACK */	static_cast<int>(TcpState::SYN_RECEIVED), /* Handshake (2): SYN-ACK is expected. */
                /* ACK */	0,
                /* FIN */	0
        }}
};

static struct TCPState ST_TCPStateSimSynSent = {
	(char*)"SIMSYN_SENT",
        {{      /* INVALID */	0,
                /* SYN */ 	static_cast<int>(TcpState::OK), /* Original SYN re-transmission. */
                /* SYNACK */	static_cast<int>(TcpState::SYN_RECEIVED), /* SYN-ACK response to simultaneous SYN. */
                /* ACK */	0,
                /* FIN */	0
        },
        {       /* INVALID */	0,
                /* SYN */ 	static_cast<int>(TcpState::OK),/* Simultaneous SYN re-transmission.*/
                /* SYNACK */	static_cast<int>(TcpState::SYN_RECEIVED), /* SYN-ACK response to original SYN. */
                /* ACK */	0,
               	/* FIN */	static_cast<int>(TcpState::FIN_SEEN)	/* FIN may be sent early. */ 
        }}
};

static struct TCPState ST_TCPStateSynReceived = {
	(char*)"SYN_RECEIVED",
        {{      /* INVALID */   0,
                /* SYN */	0,
                /* SYNACK */	0,
                /* ACK */ 	static_cast<int>(TcpState::ESTABLISHED), /* Handshake (3): ACK is expected. */
               	/* FIN */	static_cast<int>(TcpState::FIN_SEEN),	/* FIN may be sent early. */ 
        },
        {       /* INVALID */	0,
                /* SYN */	0,
                /* SYNACK */	static_cast<int>(TcpState::OK),	/* SYN-ACK may be retransmitted. */
                /* ACK */	static_cast<int>(TcpState::OK),	/* XXX: ACK of late SYN in simultaneous case? */
               	/* FIN */	static_cast<int>(TcpState::FIN_SEEN)	/* FIN may be sent early. */ 
        }}
};

static struct TCPState ST_TCPStateEstablished = {
	(char*)"ESTABLISHED",
        /*
         * Regular ACKs (data exchange) or FIN.
         * FIN packets may have ACK set.
         */
        {{      /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::OK),
                /* FIN */      	static_cast<int>(TcpState::FIN_SEEN) /* FIN by the sender. */ 
        },
        {       /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::OK),
                /* FIN */      	static_cast<int>(TcpState::FIN_SEEN) /* FIN by the receiver. */ 
        }}
};

static struct TCPState ST_TCPStateFinSeen = {
	(char*)"FIN_SEEN",
        /*
         * FIN was seen.   If ACK only, connection is half-closed now,
         * need to determine which end is closed (sender or receiver).
         * However, both FIN and FIN-ACK may race here - in which
         * case we are closing immediately.
         */
        {{      /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::CLOSE_WAIT),
                /* FIN */      	static_cast<int>(TcpState::CLOSING) 
        },
        {       /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::FIN_WAIT),
                /* FIN */       static_cast<int>(TcpState::CLOSING)
        }}
};

static struct TCPState ST_TCPStateCloseWait = {
	(char*)"CLOSE_WAIT" ,
        /* Sender has sent the FIN and closed its end. */
        {{      /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::OK),
                /* FIN */      	static_cast<int>(TcpState::LAST_ACK) 
        },
        {       /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::OK),
                /* FIN */      	static_cast<int>(TcpState::LAST_ACK) 
        }}
};

static struct TCPState ST_TCPStateFinWait = {
        (char*)"FIN_WAIT" ,
        /* Receiver has closed its end. */
        {{      /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::OK),
                /* FIN */       static_cast<int>(TcpState::LAST_ACK)
        },
        {       /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::OK),
                /* FIN */       static_cast<int>(TcpState::LAST_ACK)
        }}
};

static struct TCPState ST_TCPStateClosing = {
        (char*)"CLOSING" ,
        /* Race of FINs - expecting ACK. */
        {{      /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::LAST_ACK),
                /* FIN */      	0 
        },
        {       /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::LAST_ACK),
                /* FIN */       0
        }}
};

static struct TCPState ST_TCPStateLastAck = {
        (char*)"LAST_ACK" ,
        /* FINs exchanged - expecting last ACK. */
        {{      /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::TIME_WAIT),
                /* FIN */       0
        },
        {       /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       static_cast<int>(TcpState::TIME_WAIT),
                /* FIN */       0
        }}
};

static struct TCPState ST_TCPStateTimeWait = {
        (char*)"TIMEWAIT", 
        /* May re-open the connection as per RFC 1122. */
        {{      /* INVALID */   0,
                /* SYN */       static_cast<int>(TcpState::SYN_SENT),
                /* SYNACK */    0,
                /* ACK */       0,
                /* FIN */       0
        },
        {       /* INVALID */   0,
                /* SYN */       0,
                /* SYNACK */    0,
                /* ACK */       0,
                /* FIN */       0
        }}
};



struct ST_TCPStateMachine {
	struct TCPState *state;
};

const struct ST_TCPStateMachine tcp_states[] = {
	&ST_TCPStateClosed,
	&ST_TCPStateSynSent,
	&ST_TCPStateSimSynSent,
	&ST_TCPStateSynReceived,
	&ST_TCPStateEstablished,
	&ST_TCPStateFinSeen,
	&ST_TCPStateCloseWait,
	&ST_TCPStateFinWait,
	&ST_TCPStateClosing,
	&ST_TCPStateLastAck,
	&ST_TCPStateTimeWait,
};

} // namespace aiengine

#endif  // SRC_TCP_TCPSTATES_H_
