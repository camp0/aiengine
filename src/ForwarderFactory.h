#ifndef _ForwarderFactory_H_
#define _ForwarderFactory_H_

#include "ForwarderVisitor.h"
//#include "Protocol.h"

#include <vector>
//#include <boost/shared_ptr.hpp>

//class Mux;

class ForwarderFactory : public Forwarder
{
public:
	ConduitFactory() {}
	virtual ~ConduitFactory() {}

    	virtual void setSideA(const ForwarderPtr& side) { sideA_ = side; }
    	virtual void setSideB(const ForwarderPtr& side) { sideB_ = side; }
    	virtual const ForwarderPtrWeak& getSideA() const { return sideA_; }
    	virtual const ForwarderPtrWeak& getSideB() const { return sideB_; }

    // caller takes responsability for the returned pointer
    //virtual Conduit* getProtocol(IPmsg& msg) = 0;
    //virtual Conduit* getProtocol(TCPmsg& msg) = 0;
protected:
    	ForwarderPtrWeak sideA_;
    	ForwarderPtrWeak sideB_;

};

#endif

