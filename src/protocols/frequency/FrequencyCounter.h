/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2015  Luis Campo Giralte
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
 * Written by Luis Campo Giralte <luis.camp0.2009@gmail.com> 
 *
 */
#ifndef SRC_PROTOCOLS_FREQUENCY_FREQUENCYCOUNTER_H_
#define SRC_PROTOCOLS_FREQUENCY_FREQUENCYCOUNTER_H_ 

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <cstring>
#include "Frequencies.h"
#include "flow/FlowManager.h"

namespace aiengine {

class FrequencyCounter 
{
public:
    	explicit FrequencyCounter() {freqs_ = SharedPointer<Frequencies>(new Frequencies());reset();}
    	virtual ~FrequencyCounter() {}

	void reset() { items_ = 0; freqs_->reset(); }

	void addFrequencyComponent(SharedPointer<Frequencies> freq);

	void compute();

	WeakPointer<Frequencies> getFrequencyComponent() { return freqs_;}	

	void filterFrequencyComponent(FlowManagerPtr flow_t, std::function <bool (SharedPointer<Flow>&)> checker );

private:
	SharedPointer<Frequencies> freqs_;
     	int items_; 
};

typedef std::shared_ptr<FrequencyCounter> FrequencyCounterPtr;

} // namespace aiengine

#endif  // SRC_PROTOCOLS_FREQUENCY_FREQUENCYCOUNTER_H_
