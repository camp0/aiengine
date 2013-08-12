#include "FrequencyCounter.h"

void FrequencyCounter::addFrequencyComponent(FrequenciesPtr freq)
{	
	if(freq)
	{
		Frequencies *f1_dest = freqs_.get();
		Frequencies *f2_src = freq.get();

		*f1_dest = *f1_dest + *f2_src;
		++items_;
	}
} 

void FrequencyCounter::compute()
{
	Frequencies *f_dest = freqs_.get();

	if(items_ > 0)
		*f_dest = *f_dest / items_;
}

void filterFrequencyComponent(FlowManager ptr,std::function <bool (Packet&)> condition) 
{

}
 
