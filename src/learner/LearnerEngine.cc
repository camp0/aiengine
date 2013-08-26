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
#include "LearnerEngine.h"

void LearnerEngine::statistics(std::basic_ostream<char>& out)
{
	out << "Learner statistics" << std::endl;
	for(int i = 0;i< 300;++i)
	{
		for (auto it = q_array_[i].begin(); it!=q_array_[i].end();++it)
		{
			out << "(" <<i <<")[" << hex << it->first << "," << dec << it->second << "]" <<std::endl;
		}	
	}
}

void LearnerEngine::agregatePacketFlow(PacketFrequenciesPtr pkt_freq)
{
	++items_;

	for(int i = 0;i< pkt_freq->getLength();++i)
	{
		int value = pkt_freq->index(i);

		auto it = q_array_[i].find(value);	
		if(it == q_array_[i].end()) 
		{
			q_array_[i].insert(std::make_pair(value,1));
		//	int *j = std::get<int>(it->first);	
		}
		else
		{
			auto leches = it->second;
			int *j = &it->second;
			++(*j);
			//int *j = &std::get<1>(it->second);	
		}		
	}
}

int LearnerEngine::getQualityByte(int offset)
{
	int quality = 0;

	if(offset < 5000)
	{
		int items = q_array_[offset].size();
	
		if(items_>0)
		{
			quality = (items*100)/items_;
		}	
	}
	return quality;
}

void LearnerEngine::compute()
{


}
