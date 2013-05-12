#ifndef _Multiplexer_H_
#define _Multiplexer_H_

#include <iostream>
#include <vector>
#include <map>

#include "Forwarder.h"
#include "Accessor.h"
#include "ForwarderFactory.h"

class Multiplexer : public Forwarder
{
public:
    	Multiplexer(Accessor& accessor, ForwarderFactory& sideBfactory) :
        	accessor_(accessor),
        	sideBfactory_(sideBfactory)
    	{
    	}
    	virtual ~Multiplexer();

    	virtual void setSideA(const ForwarderPtr& side) { sideA_ = side;} 
    	virtual void setSideB(const ForwarderPtr& side) { throw "Multiplexer has multiple side B";}
    	virtual const ForwarderPtrWeak& getSideA() const;
    	virtual const ForwarderPtrWeak& getSideB() const;

    	virtual const Forwarder& getSideB(int key);

    	void addSideB(int key, Forwarder* sideB);

    	virtual const ForwarderFactory& getFactory() const;
    	virtual const Forwarder& getAccessor() const;

protected:
    	Accessor& accessor_;
    	ForwarderFactory& sideBfactory_;

	ForwarderPtrWeak sideA_;	

    	typedef std::map<int,Forwarder*> MapSideB;
    	MapSideB sideBlist_;
};

class UnhandledPktMux : public Multiplexer
{
public:
    	UnhandledPktMux(Accessor& accessor, ForwarderFactory& sideBfactory) :
    		Multiplexer(accessor, sideBfactory)
	{
	}
    	virtual ~UnhandledPktMux() {}

    	void visit(IPmsg& msg) {}
    	void visit(TCPmsg& pkt) { throw "UnhandledPktMux can not handle TCP messages"; }
    	void visit(UDPmsg& p) { throw "UnhandledPktMux can not handle UDP messages"; }
    	void visit(HTTPmsg& p) { throw "UnhandledPktMux can not handle HTTP messages"; }
};


#endif
