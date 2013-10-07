/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 2013
 *
 */
#ifndef _NetworkStack_H_
#define _NetworkStack_H_

#include <iostream>
#include <fstream>
#include "Multiplexer.h"
//#include "./names/DomainNameManager.h"
#include "./regex/RegexManager.h"
#include "./flow/FlowManager.h"

class NetworkStack 
{
public:
    	NetworkStack() {};
    	virtual ~NetworkStack() {};

	virtual void printFlows(std::basic_ostream<char>& out) = 0;
	virtual void printFlows() = 0;

	virtual void setStatisticsLevel(int level) = 0;
	virtual void statistics(std::basic_ostream<char>& out) = 0;
	virtual void statistics() = 0;

	virtual const char* getName() = 0;
	virtual void setName(char *name) = 0;

	void virtual setLinkLayerMultiplexer(MultiplexerPtrWeak mux) = 0;
	MultiplexerPtrWeak virtual getLinkLayerMultiplexer() = 0; 

	virtual void setTotalTCPFlows(int value) = 0;
	virtual void setTotalUDPFlows(int value) = 0;

	virtual void setTCPRegexManager(RegexManagerPtrWeak sig) = 0;	
	virtual void setUDPRegexManager(RegexManagerPtrWeak sig) = 0;	
	virtual void setTCPRegexManager(RegexManager& sig) = 0;	
	virtual void setUDPRegexManager(RegexManager& sig) = 0;	
//	virtual void setDNSDomainNameManager(DomainNameManagerPtrWeak dnm) = 0;
//	virtual void setDNSDomainNameManager(DomainNameManager& dnm) = 0;

	virtual void enableFrequencyEngine(bool enable) = 0;
	virtual void enableNIDSEngine(bool enable) = 0;
	virtual void enableLinkLayerTagging(std::string type) = 0;

#ifdef PYTHON_BINDING
	virtual FlowManager& getTCPFlowManager() = 0;
	virtual FlowManager& getUDPFlowManager() = 0;
#else
	virtual FlowManagerPtrWeak getTCPFlowManager() = 0;
	virtual FlowManagerPtrWeak getUDPFlowManager() = 0;
#endif

};

typedef std::shared_ptr <NetworkStack> NetworkStackPtr;

#endif
