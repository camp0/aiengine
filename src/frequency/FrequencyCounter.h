#ifndef _FrequencyCounter_H_
#define _FrequencyCounter_H_

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <iostream>
#include <cstring>
#include "Frequencies.h"
#include "../flow/FlowManager.h"

using namespace std;

class FrequencyCounter 
{
public:
    	explicit FrequencyCounter() {freqs_ = FrequenciesPtr(new Frequencies());reset();};
    	virtual ~FrequencyCounter() {};

	void reset() { items_ = 0;freqs_->reset(); };
	void addFrequencyComponent(FrequenciesPtr freq)
	{	
		if(freq)
		{
        		Frequencies *f1_dest = freqs_.get();
        		Frequencies *f2_src = freq.get();
        
			*f1_dest = *f1_dest + *f2_src;
			++items_;
		}
	} 

	void compute()
	{
        	Frequencies *f_dest = freqs_.get();

		if(items_ > 0)
			*f_dest = *f_dest / items_;
	}

	FrequenciesPtrWeak getFrequencyComponent() { return freqs_;};	

	void filterFrequencyComponent(FlowManagerPtr flow_t, std::function <bool (FlowPtr&)> checker )
	{
		auto ft = flow_t->getFlowTable();
		for (auto it = ft.begin(); it!=ft.end();++it)
		{
			FlowPtr flow = *it;
			if(flow->frequencies.lock())
			{
				if(checker(flow))
				{
					FrequenciesPtr freq = flow->frequencies.lock();

					if(freq)
						addFrequencyComponent(freq);
				}
			}
		}	
	}

private:
	FrequenciesPtr freqs_;
     	int items_; 
};

typedef std::shared_ptr<FrequencyCounter> FrequencyCounterPtr;

#endif
