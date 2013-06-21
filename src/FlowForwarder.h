#ifndef _FlowForwarder_H_
#define _FlowForwarder_H_

#include <iostream>
#include <memory>
#include <functional>
#include <map>
#include "./flow/Flow.h"

class Protocol;
typedef std::shared_ptr<Protocol> ProtocolPtr;

class FlowForwarder;
typedef std::shared_ptr<FlowForwarder> FlowForwarderPtr; 
typedef std::weak_ptr<FlowForwarder> FlowForwarderPtrWeak; 

class FlowForwarder 
{
public:
    	FlowForwarder(): packet_()
	{
		total_forward_flows_ = 0;
		total_received_flows_ = 0;
		total_fail_flows_ = 0;
		protocol_id_ =  NO_PROTOCOL_SELECTED;
		addChecker(std::bind(&FlowForwarder::default_check,this));
		addPacketFunction(std::bind(&FlowForwarder::default_packet_func,this));
	}
    	virtual ~FlowForwarder() {};

    	void virtual addUpFlowForwarder(FlowForwarderPtrWeak mux)
	{
		muxUpMap_[0] = mux;
	}

	void virtual addDownFlowForwarder(FlowForwarderPtrWeak mux)
	{
		muxDown_ = mux;
	}

	FlowForwarderPtrWeak getDownFlowForwarder() const; 
	FlowForwarderPtrWeak getUpFlowForwarder(int key) const;

	void forwardFlow(Flow *flow);

        void statistics(std::basic_ostream<char>& out);
        void statistics() { statistics(std::cout);};

	int getNumberUpFlowForwarders() const { return muxUpMap_.size(); }

	void setProtocol(ProtocolPtr proto){ proto_ = proto; };
	ProtocolPtr getProtocol() { return proto_;};

	void addChecker(std::function <bool ()> checker){ check_func_ = checker;};
	void addPacketFunction(std::function <void ()> packet_func){ packet_func_ = packet_func;};

	uint64_t getTotalForwardFlows() const { return total_forward_flows_;};
	uint64_t getTotalFailFlows() const { return total_fail_flows_;};
	uint64_t getTotalReceivedFlows() const { return total_received_flows_;};

	bool acceptFlow() const { return check_func_();};

private:
	ProtocolPtr proto_;
	bool default_check() const { return true;};
	void default_packet_func() const { };
	uint64_t total_received_flows_;
	uint64_t total_forward_flows_;
	uint64_t total_fail_flows_;
	FlowForwarderPtrWeak muxDown_;
	u_int16_t protocol_id_; // the protocol analiyzer owned by the multiplexer
    	typedef std::vector<FlowForwarderPtrWeak> MuxVector;
	MuxVector muxUpVector_;
	std::function <bool ()> check_func_;	
	std::function <void ()> packet_func_;	
};


#endif
