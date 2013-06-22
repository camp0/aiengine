#ifndef _FlowForwarder_H_
#define _FlowForwarder_H_

#include <iostream>
#include <memory>
#include <functional>
#include <list>
#include "./flow/Flow.h"

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
		addFlowFunction(std::bind(&FlowForwarder::default_flow_func,this,std::placeholders::_1));
	}
    	virtual ~FlowForwarder() {};

    	void virtual addUpFlowForwarder(FlowForwarderPtrWeak mux)
	{
		muxUpVector_.push_back(mux);
	}

	void virtual addDownFlowForwarder(FlowForwarderPtrWeak mux)
	{
		muxDown_ = mux;
	}

	void forwardFlow(Flow *flow);

        void statistics(std::basic_ostream<char>& out);
        void statistics() { statistics(std::cout);};

	void setProtocol(ProtocolPtr proto){ proto_ = proto; };
	ProtocolPtr getProtocol() { return proto_;};

	void addFlowFunction(std::function <void (Flow*)> flow_func){ flow_func_ = flow_func;};

	uint64_t getTotalForwardFlows() const { return total_forward_flows_;};
	uint64_t getTotalFailFlows() const { return total_fail_flows_;};
	uint64_t getTotalReceivedFlows() const { return total_received_flows_;};

private:
	ProtocolPtr proto_;
	void default_flow_func(Flow*) const { };
	uint64_t total_received_flows_;
	uint64_t total_forward_flows_;
	uint64_t total_fail_flows_;
	FlowForwarderPtrWeak muxDown_;
	u_int16_t protocol_id_; // the protocol analiyzer owned by the multiplexer
    	typedef std::list<FlowForwarderPtrWeak> MuxVector;
	MuxVector muxUpVector_;
	std::function <void (Flow*)> flow_func_;	
};


#endif
