#include "Multiplexer.h"

Multiplexer::~Multiplexer()
{
	MapSideB::iterator iter = sideBlist_.begin();
        for( ; iter != sideBlist_.end(); iter++) {
        	delete (*iter).second;
        }
        sideBlist_.clear();
}

const ForwarderPtrWeak& Multiplexer::getSideA() const 
{ 
	return sideA_; 
}

const ForwarderPtrWeak& Multiplexer::getSideB() const
{
        throw "Multiplexerx has multiple side B";
        return sideA_; // to prevent compile errors
}

const Forwarder& Multiplexer::getSideB(int key)
{
	MapSideB::iterator it = sideBlist_.find(key);
        return *(it->second);
}

void Multiplexer::addSideB(int key, Forwarder* sideB) 
{
        if (sideB) {
            sideBlist_[key] = sideB;
        }
}

const ForwarderFactory& Multiplexer::getFactory() const 
{ 
	return sideBfactory_; 
}

const Forwarder& Multiplexer::getAccessor() const 
{ 
	return accessor_; 
}



