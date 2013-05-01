#ifndef _FlowManager_H_
#define _FlowManager_H_

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>

#include <fstream>
#include <vector>
#include <list>

#include "Flow.h"

// define a multi_index_container with a list-like index and an ordered index
typedef boost::multi_index_container<
	flow*,
		boost::multi_index::indexed_by<
    		boost::multi_index::sequenced<>, // list-like index
    		boost::multi_index::ordered_non_unique<boost::multi_index::identity<flow*> > 
  	>
> flow_container;


class FlowManager
{
public:
    	FlowManager(std::ofstream& logfile);
    	virtual ~FlowManager();

	const static int inactivityTime_ = 180; // seconds
    	typedef std::vector<flow*> InactiveConnections;

    	/// moves connection from active map to inactive list
    	virtual bool inactivateFlow(flow* f, bool removeTimer=true);
    	virtual void inactivateAllFlows();

	InactiveFlows* getInactiveTcpFlows() { return &comotoseTCPflows_; }
    	InactiveFlows* getInactiveUdpFlowss() { return &comotoseUDPflows_; }

    	inline bool hasMoreInactiveTcpConnections() const { return !comotoseTCPconnections_.empty(); }
    	inline bool hasMoreInactiveUdpConnections() const { return !comotoseUDPconnections_.empty(); }
    	inline flow* popInactiveTcpConnectionBack() {
        	flow* f = comotoseTCPflows_.back();
        	comotoseTCPflows_.pop_back();
        	return f;
    	}
    	inline flow* popInactiveUdpConnectionBack() {
        	flow* f = comotoseUDPflows_.back();
        	comotoseUDPflows_.pop_back();
        	return f;
    	}
    
	flow* findFlow(unsigned long hash, const 5tuple& id);
    	bool insertFlow(unsigned long hash, flow* f);

    	inline timeval getTimeStamp() const { return now_; }
    	void setTimeStamp(timeval now);

private:
	std::ofstream& logfile_;
    	bool debug_;
    	timeval now_;
    	std::string lastTraceFile_;

    	typedef __gnu_cxx::hash_multimap<unsigned long,flow*> FlowMap;
    	typedef FlowMap::value_type value_type;
    	FlowMap flowMap_;
    
	/// a list of dead or inactive connections. 
	/// Connections are moved from the active map here when a tcp connection has been
    	/// closed or when the connection has become inactive

	InactiveConnections comotoseTCPconnections_;
    	InactiveConnections comotoseUDPconnections_;

    	flow_container timers_;

    	void timeout(const timeval& now);

};

#endif
