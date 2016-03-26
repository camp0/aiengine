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
#ifndef SRC_PROTOCOL_H_
#define SRC_PROTOCOL_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_LIBLOG4CXX
#include "log4cxx/logger.h"
#endif

#if defined(RUBY_BINDING)
#include <ruby.h>
#endif

#include <sys/types.h>
#if defined(__OPENBSD__)
#include <netinet/in_systm.h>
#include <net/ethertypes.h>
#else
#include <net/ethernet.h>
#endif

#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <boost/utility/string_ref.hpp>
#include "Pointer.h"
#include "FlowForwarder.h"
#include "Multiplexer.h"
#include "DatabaseAdaptor.h"
#include "./ipset/IPSetManager.h"
#include "names/DomainNameManager.h"
#include "CacheManager.h"

namespace aiengine {

class Flow;

typedef std::pair<SharedPointer<StringCache>,int32_t> StringCacheHits;
typedef std::map<boost::string_ref,StringCacheHits> GenericMapType;
typedef std::pair<boost::string_ref,StringCacheHits> PairStringCacheHits; 

static std::function <void(int&,std::string&)> unitConverter = [](int &bytes,std::string &unit) noexcept { 
	if (bytes >1024) { bytes = bytes / 1024; unit = "KBytes"; } 
	if (bytes >1024) { bytes = bytes / 1024; unit = "MBytes"; } 
	if (bytes >1024) { bytes = bytes / 1024; unit = "GBytes"; } 
};

#if defined(PYTHON_BINDING) 

#define addValueToCounter(h,key,value) h[key] = value;

#elif defined(JAVA_BINDING)

#define addValueToCounter(h,key,value) h[key] = value;
typedef std::map<std::string,int32_t> JavaCounters;

#elif defined(RUBY_BINDING)

typedef struct ruby_shared_data {
        VALUE obj;
	ID method_id;
	int nargs;
	VALUE args[4];
} ruby_shared_data;

#define addValueToCounter(h,key,value) rb_hash_aset(h,rb_str_new2(key),INT2NUM(value)); 

#endif

class Protocol 
{
public:
    	explicit Protocol(const std::string& name, const std::string& short_name):
		ipset_mng_(),
		total_malformed_packets_(0),total_validated_packets_(0),
		total_packets_(0),
		mux_(), flow_forwarder_(),
		name_(name),short_name_(short_name),
		protocol_id_(0)
#ifdef PYTHON_BINDING
		,dbptr_(),is_set_db_(false),packet_sampling_(32)
#elif defined(RUBY_BINDING)
		,dbptr_(Qnil),is_set_db_(false),packet_sampling_(32)
#elif defined(JAVA_BINDING)
		,dbptr_(nullptr),is_set_db_(false),packet_sampling_(32)
#endif
		{}

    	virtual ~Protocol() { ipset_mng_.reset(); name_.clear(); short_name_.clear(); }

	virtual void setHeader(unsigned char *raw_packet) = 0;
	virtual void setStatisticsLevel(int level) = 0;
	virtual void statistics(std::basic_ostream<char>& out) = 0;
	virtual void statistics() = 0;

	const char* getName() { return name_.c_str();} 
	const char* getShortName() { return short_name_.c_str();} 

	virtual void processFlow(Flow *flow) = 0;
	virtual bool processPacket(Packet &packet) = 0;

	void setMultiplexer(MultiplexerPtrWeak mux) { mux_ = mux; }
	MultiplexerPtrWeak getMultiplexer() { return mux_; } 

	void setFlowForwarder(WeakPointer<FlowForwarder> ff) { flow_forwarder_ = ff; }
	WeakPointer<FlowForwarder> getFlowForwarder() { return flow_forwarder_; } 

	void infoMessage(const std::string& msg);

	// Clear cache resources
	virtual void releaseCache() = 0;

	// Memory comsumption of the Protocol, caches and so on
	virtual int64_t getAllocatedMemory() const = 0;

	// used on mainly on the bindings
	virtual void increaseAllocatedMemory(int value) {}
	virtual void decreaseAllocatedMemory(int value) {}

        virtual void setDomainNameManager(DomainNameManagerPtrWeak dnm) {} // Non pure virtual methods
        virtual void setDomainNameBanManager(DomainNameManagerPtrWeak dnm) {}

	virtual void addRejectFunction(std::function <void (Flow*)> reject) {}

	virtual void setAnomalyManager(SharedPointer<AnomalyManager> amng) {}
	virtual void setCacheManager(SharedPointer<CacheManager> cmng) {}

#if defined(PYTHON_BINDING)
        virtual boost::python::dict getCounters() const = 0;
	virtual boost::python::dict getCache() const { return boost::python::dict(); }

	void setDatabaseAdaptor(boost::python::object &dbptr, int packet_sampling);  

	boost::python::dict addMapToHash(const GenericMapType &mt) const;

#elif defined(RUBY_BINDING)
        virtual VALUE getCounters() const = 0;
	virtual VALUE getCache() const { return Qnil; }
	void setDatabaseAdaptor(VALUE dbptr, int packet_sampling);  
	
	VALUE addMapToHash(const GenericMapType &mt) const;
#elif defined(JAVA_BINDING)

	void setDatabaseAdaptor(DatabaseAdaptor *dbptr, int packet_sampling);
	virtual JavaCounters getCounters() const = 0;
#endif

#if defined(PYTHON_BINDING) || defined(RUBY_BINDING) || defined(JAVA_BINDING)

	bool getDatabaseObjectIsSet() const { return is_set_db_;}
	int getPacketSampling() const { return packet_sampling_;}

#if defined(HAVE_ADAPTOR)
	void databaseAdaptorInsertHandler(Flow *flow);
	void databaseAdaptorUpdateHandler(Flow *flow); 
	void databaseAdaptorRemoveHandler(Flow *flow); 
#endif
#endif

	void setIPSetManager(const SharedPointer<IPSetManager> ipset_mng) { ipset_mng_ = ipset_mng;} 

	// Helper for show the content of cache of StringCache types
	void showCacheMap(std::basic_ostream<char>& out,GenericMapType &mt, const std::string &title, const std::string &item_name);

	SharedPointer<IPSetManager> ipset_mng_;
	mutable int64_t total_malformed_packets_;
	mutable int64_t total_validated_packets_;
	mutable int64_t total_packets_;
        MultiplexerPtrWeak mux_;
        WeakPointer<FlowForwarder> flow_forwarder_;
private:
	std::string name_;
	std::string short_name_;
	uint16_t protocol_id_;
#ifdef PYTHON_BINDING
        boost::python::object dbptr_;
        bool is_set_db_;
	int packet_sampling_;
#elif defined(RUBY_BINDING)
	VALUE dbptr_;
	bool is_set_db_;
	int packet_sampling_;
#elif defined(JAVA_BINDING)
	DatabaseAdaptor *dbptr_;
	bool is_set_db_;
	int packet_sampling_;
#endif

#ifdef HAVE_LIBLOG4CXX
        static log4cxx::LoggerPtr logger;
#endif
};

typedef std::shared_ptr <Protocol> ProtocolPtr;
typedef std::weak_ptr <Protocol> ProtocolPtrWeak;

} // namespace aiengine  

#endif  // SRC_PROTOCOL_H_
