/*
 * AIEngine a deep packet inspector reverse engineering engine.
 *
 * Copyright (C) 2013-2014  Luis Campo Giralte
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
#include "FrequencyCounter.h"

namespace aiengine {

void FrequencyCounter::addFrequencyComponent(SharedPointer<Frequencies> freq) {

	if(freq) {
		Frequencies *f1_dest = freqs_.get();
		Frequencies *f2_src = freq.get();

		*f1_dest = *f1_dest + *f2_src;
		++items_;
	}
} 

void FrequencyCounter::compute() {

	Frequencies *f_dest = freqs_.get();

	if (items_ > 0) {
		*f_dest = *f_dest / items_;
	}
}

void FrequencyCounter::filterFrequencyComponent(FlowManagerPtr flow_t, std::function <bool (SharedPointer<Flow>&)> checker ) {

	auto ft = flow_t->getFlowTable();

	for (auto it = ft.begin(); it!=ft.end();++it) {
		SharedPointer<Flow> flow = *it;
		if (flow->frequencies.lock()) {
			if (checker(flow)) {
				SharedPointer<Frequencies> freq = flow->frequencies.lock();

				if(freq)
					addFrequencyComponent(freq);
			}
		}
	}
}

} // namespace aiengine
