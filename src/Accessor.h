#ifndef _Accessor_H_
#define _Accessor_H_

#include "Forwarder.h"

class Accessor : public Forwarder 
{
public:
	Accessor() {};
	virtual ~Accessor() {};

	virtual void setSideA(const ForwarderPtr& side) { throw "Accessor has multiple side A"; }
    	virtual void setSideB(const ForwarderPtr& side) { throw "Accessor has multiple side B"; }

    	virtual const ForwarderPtrWeak& getSideA() const
    	{
        	throw "Accessor has multiple side B";
        	return sideA_; // to prevent compile errors
    	}
    	virtual const ForwarderPtrWeak& getSideB() const
    	{
        	throw "Accessor has multiple side B";
        	return sideA_; // to prevent compile errors
    	}

private:
	ForwarderPtrWeak sideA_;
};

#endif
