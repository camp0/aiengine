#ifndef _FlowForwarder_H_
#define _FlowForwarder_H_

#include <iostream>
#include <memory>
#include <functional>
#include <vector>
#include "./flow/Flow.h"
#include "Packet.h"

class Protocol;
typedef std::shared_ptr<Protocol> ProtocolPtr;

class FlowForwarder;
typedef std::shared_ptr<FlowForwarder> FlowForwarderPtr; 
typedef std::weak_ptr<FlowForwarder> FlowForwarderPtrWeak; 

class FlowForwarder 
{
public:
    	FlowForwarder() 
	{
		total_forward_flows_ = 0;
		total_received_flows_ = 0;
		total_fail_flows_ = 0;
		protocol_id_ =  0;
		addChecker(std::bind(&FlowForwarder::default_check,this,std::placeholders::_1));
		addFlowFunction(std::bind(&FlowForwarder::default_flow_func,this,std::placeholders::_1));
	}
    	virtual ~FlowForwarder() {};

    	void virtual addUpFlowForwarder(FlowForwarderPtrWeak mux)
	{
		flowForwarderVector_.push_back(mux);
	}

	void forwardFlow(Flow *flow);

        void statistics(std::basic_ostream<char>& out);
        void statistics() { statistics(std::cout);};

	void setProtocol(ProtocolPtr proto){ proto_ = proto; };
	ProtocolPtr getProtocol() { return proto_;};

	bool acceptPacket(Packet& packet) const { return check_func_(packet);};
	void addChecker(std::function <bool (Packet&)> checker){ check_func_ = checker;};
	void addFlowFunction(std::function <void (Flow*)> flow_func){ flow_func_ = flow_func;};

	uint64_t getTotalForwardFlows() const { return total_forward_flows_;};
	uint64_t getTotalFailFlows() const { return total_fail_flows_;};
	uint64_t getTotalReceivedFlows() const { return total_received_flows_;};

private:
	ProtocolPtr proto_;
	bool default_check(Packet&) const { return true;};
	void default_flow_func(Flow*) const { };
	uint64_t total_received_flows_;
	uint64_t total_forward_flows_;
	uint64_t total_fail_flows_;
	FlowForwarderPtrWeak muxDown_;
	u_int16_t protocol_id_; // the protocol analiyzer owned by the multiplexer
    	std::vector<FlowForwarderPtrWeak> flowForwarderVector_;
	std::function <void (Flow*)> flow_func_;
	std::function <bool (Packet&)> check_func_;	
};


#endif
