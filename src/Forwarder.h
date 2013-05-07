#ifndef _Forwarder_H_
#define _Forwarder_H_

#include <boost/weak_ptr.hpp>

#include "ForwarderVisitor.h"

class Forwarder : public ForwarderVisitor
{
public:
	Forwarder() {}
    	virtual ~Forwarder() {}

	virtual void setSideA(const ForwarderPtr& side) = 0;
    	virtual void setSideB(const ForwarderPtr& side) = 0;
    	virtual const ForwarderPtrWeak& getSideA() const = 0;
    	virtual const ForwarderPtrWeak& getSideB() const = 0;
};

typedef boost::shared_ptr<Forwarder> ForwarderPtr;
typedef boost::weak_ptr<Forwarder> ForwarderPtrWeak;

#endif
