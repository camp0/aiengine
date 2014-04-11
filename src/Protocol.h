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
#ifndef SRC_PROTOCOL_H_
#define SRC_PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <fstream>
#include "Pointer.h"
#include "FlowForwarder.h"
#include "Multiplexer.h"
#include "DatabaseAdaptor.h"
#include "./ipset/IPSet.h"

namespace aiengine {

class Flow;

class Protocol 
{
public:
    	Protocol():total_malformed_packets_(0),total_validated_packets_(0),
		total_packets_(0),ipset_(),
#ifdef PYTHON_BINDING
		dbptr_(),is_set_db_(false),packet_sampling_(32),
#endif
		name_("") {}
    	virtual ~Protocol() { ipset_.reset();}

	virtual void setHeader(unsigned char *raw_packet) = 0;
	virtual void setStatisticsLevel(int level) = 0;
	virtual void statistics(std::basic_ostream<char>& out) = 0;
	virtual void statistics() = 0;
	virtual const char* getName() = 0;

	virtual void processFlow(Flow *flow) = 0;
	virtual void processPacket(Packet &packet) = 0;

	virtual void setMultiplexer(MultiplexerPtrWeak mux) = 0;
	virtual MultiplexerPtrWeak getMultiplexer() = 0; 

	virtual void setFlowForwarder(FlowForwarderPtrWeak ff) = 0;
	virtual FlowForwarderPtrWeak getFlowForwarder() = 0; 

#ifdef PYTHON_BINDING
	void setDatabaseAdaptor(boost::python::object &dbptr) { setDatabaseAdaptor(dbptr,16); }
	void setDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling) { dbptr_ = dbptr; is_set_db_ = true; packet_sampling_ = packet_sampling; }

        mutable boost::python::object dbptr_;
        mutable bool is_set_db_;
	mutable int packet_sampling_;

	void setIPSet(const IPSet& ipset) { ipset_ = boost::make_shared<IPSet>(ipset);} 
#else
	void setIPSet(SharedPointer<IPSet> ipset) { ipset_ = ipset;} 
#endif

	SharedPointer<IPSet> ipset_;
	mutable std::string name_;
	mutable int64_t total_malformed_packets_;
	mutable int64_t total_validated_packets_;
	mutable int64_t total_packets_;
private:
	u_int16_t protocol_id_;
};

typedef std::shared_ptr <Protocol> ProtocolPtr;

} // namespace aiengine  

#endif  // SRC_PROTOCOL_H_
